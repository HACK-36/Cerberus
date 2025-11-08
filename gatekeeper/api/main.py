"""
Gatekeeper API Service
Main WAF component with ML triage and rule management
"""
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional, Literal
import sys
import os
from datetime import datetime
import json

# Add parent directories to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from gatekeeper.ml.feature_extractor import FeatureExtractor
from gatekeeper.ml.anomaly_detector import AnomalyDetector, LSTMBehavioralClassifier
from shared.events.schemas import (
    POITaggedEvent, RequestData, ScoreData, GeoIPData, WAFRule
)

app = FastAPI(
    title="Cerberus Gatekeeper API",
    description="WAF with ML-based anomaly detection",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Initialize ML components
feature_extractor = FeatureExtractor()
anomaly_detector = AnomalyDetector()
behavioral_classifier = LSTMBehavioralClassifier()

# In-memory rule storage (in production, use Redis/PostgreSQL)
active_rules: Dict[str, WAFRule] = {}

# Session history for behavioral analysis (in production, use Redis)
session_history: Dict[str, List[Dict]] = {}


# Request/Response models

class InspectRequest(BaseModel):
    """Request to inspect for threats"""
    method: str
    url: str
    headers: Dict[str, str]
    body: str = ""
    query_params: Dict[str, str] = {}
    client_ip: str
    session_id: str
    metadata: Dict = {}


class InspectResponse(BaseModel):
    """Inspection result"""
    action: Literal["allow", "block", "tag_poi"]
    session_id: str
    scores: ScoreData
    tags: List[str]
    reason: str
    event_id: Optional[str] = None


class RuleCreateRequest(BaseModel):
    """Create new WAF rule"""
    rule: WAFRule


class RuleListResponse(BaseModel):
    """List of rules"""
    rules: List[WAFRule]
    count: int


# API endpoints

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "gatekeeper",
        "timestamp": datetime.utcnow().isoformat(),
        "ml_model": anomaly_detector.get_model_info()
    }


@app.post("/api/v1/inspect", response_model=InspectResponse)
async def inspect_request(req: InspectRequest):
    """
    Inspect a request for threats
    
    This is the main entry point for WAF analysis
    """
    # Step 1: Check against existing WAF rules
    modsecurity_score, blocked_by_rule = check_waf_rules(req)
    
    if blocked_by_rule:
        return InspectResponse(
            action="block",
            session_id=req.session_id,
            scores=ScoreData(modsecurity=modsecurity_score, ml_anomaly=0.0, combined=modsecurity_score),
            tags=["blocked", "rule_match"],
            reason=f"Blocked by rule: {blocked_by_rule}",
            event_id=None
        )
    
    # Step 2: Extract features for ML
    request_dict = {
        "method": req.method,
        "url": req.url,
        "headers": req.headers,
        "body": req.body,
        "query_params": req.query_params,
        "metadata": req.metadata
    }
    
    features = feature_extractor.extract(request_dict)
    
    # Step 3: ML anomaly detection
    ml_score, is_anomaly = anomaly_detector.predict(features)
    
    # Step 4: Behavioral analysis (if session history exists)
    behavioral_score = 0.0
    if req.session_id in session_history:
        history = session_history[req.session_id]
        behavioral_score = behavioral_classifier.predict(history)
    
    # Update session history
    if req.session_id not in session_history:
        session_history[req.session_id] = []
    
    session_history[req.session_id].append({
        "timestamp": datetime.utcnow().isoformat(),
        "ml_score": ml_score,
        "features": features
    })
    
    # Keep only last 20 requests per session
    if len(session_history[req.session_id]) > 20:
        session_history[req.session_id] = session_history[req.session_id][-20:]
    
    # Step 5: Combined decision
    combined_score = calculate_combined_score(modsecurity_score, ml_score, behavioral_score)
    
    scores = ScoreData(
        modsecurity=modsecurity_score,
        ml_anomaly=ml_score,
        combined=combined_score
    )
    
    # Determine action and tags
    action, tags, reason = determine_action(scores, is_anomaly, behavioral_score)
    
    # If tagged as POI, emit event
    event_id = None
    if action == "tag_poi":
        event_id = emit_poi_event(req, scores, tags)
    
    return InspectResponse(
        action=action,
        session_id=req.session_id,
        scores=scores,
        tags=tags,
        reason=reason,
        event_id=event_id
    )


@app.post("/api/v1/gatekeeper/rules", status_code=201)
async def create_rule(
    req: RuleCreateRequest,
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    """
    Create a new WAF rule
    
    Requires authentication (mTLS or Bearer token in production)
    """
    # In production: verify credentials, check RBAC
    
    rule = req.rule
    
    # Validate rule
    if rule.rule_id in active_rules:
        raise HTTPException(status_code=409, detail="Rule ID already exists")
    
    # Add rule
    active_rules[rule.rule_id] = rule
    
    # In production: persist to database and hot-reload NGINX
    print(f"Rule created: {rule.rule_id} (confidence: {rule.confidence})")
    
    return {
        "rule_id": rule.rule_id,
        "status": "created",
        "message": "Rule added successfully"
    }


@app.get("/api/v1/gatekeeper/rules", response_model=RuleListResponse)
async def list_rules():
    """List all active WAF rules"""
    rules = [rule for rule in active_rules.values() if rule.enabled]
    return RuleListResponse(rules=rules, count=len(rules))


@app.get("/api/v1/gatekeeper/rules/{rule_id}")
async def get_rule(rule_id: str):
    """Get a specific rule"""
    if rule_id not in active_rules:
        raise HTTPException(status_code=404, detail="Rule not found")
    return active_rules[rule_id]


@app.delete("/api/v1/gatekeeper/rules/{rule_id}")
async def delete_rule(
    rule_id: str,
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    """Delete a WAF rule"""
    if rule_id not in active_rules:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    del active_rules[rule_id]
    
    print(f"Rule deleted: {rule_id}")
    
    return {"rule_id": rule_id, "status": "deleted"}


@app.put("/api/v1/gatekeeper/rules/{rule_id}/toggle")
async def toggle_rule(
    rule_id: str,
    enabled: bool,
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    """Enable or disable a rule"""
    if rule_id not in active_rules:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    active_rules[rule_id].enabled = enabled
    
    return {
        "rule_id": rule_id,
        "enabled": enabled,
        "status": "updated"
    }


@app.get("/api/v1/gatekeeper/stats")
async def get_stats():
    """Get Gatekeeper statistics"""
    return {
        "active_rules": len([r for r in active_rules.values() if r.enabled]),
        "total_rules": len(active_rules),
        "active_sessions": len(session_history),
        "ml_model": anomaly_detector.get_model_info(),
        "uptime": "N/A"  # In production: calculate from start time
    }


# Helper functions

def check_waf_rules(req: InspectRequest) -> tuple[float, Optional[str]]:
    """
    Check request against active WAF rules
    
    Returns (score, blocked_by_rule_id or None)
    """
    combined_text = f"{req.url} {req.body} {json.dumps(req.headers)}"
    score = 0.0
    
    for rule_id, rule in active_rules.items():
        if not rule.enabled:
            continue
        
        if rule.match.type == "string":
            if rule.match.pattern in combined_text:
                if rule.action == "block":
                    return 100.0, rule_id
                score = max(score, 80.0)
        
        elif rule.match.type == "regex":
            import re
            flags = re.IGNORECASE if rule.match.flags.get("caseless") else 0
            if re.search(rule.match.pattern, combined_text, flags):
                if rule.action == "block":
                    return 100.0, rule_id
                score = max(score, 85.0)

    heuristic_score = _heuristic_modsecurity_score(combined_text)
    score = max(score, heuristic_score)

    return score, None


def _heuristic_modsecurity_score(combined_text: str) -> float:
    """Approximate ModSecurity scoring for common attack signatures."""
    text_lower = combined_text.lower()
    score = 0.0

    # SQL injection patterns
    if "' or '" in text_lower or '" or "' in text_lower:
        score = max(score, 80.0)
    if "' and '" in text_lower or '" and "' in text_lower:
        score = max(score, 70.0)
    if "union" in text_lower and "select" in text_lower:
        score = max(score, 90.0)
    if "information_schema" in text_lower or "benchmark" in text_lower or "sleep(" in text_lower:
        score = max(score, 85.0)

    # Path traversal
    if "../" in text_lower or "..\\" in text_lower:
        score = max(score, 75.0)

    # Command injection
    if any(cmd in text_lower for cmd in [";", "&&", "||", "|", "`"]):
        if "rm " in text_lower or "cat /etc/passwd" in text_lower:
            score = max(score, 80.0)

    return score


def calculate_combined_score(modsec: float, ml: float, behavioral: float) -> float:
    """Calculate combined threat score"""
    # Weighted combination
    combined = (modsec * 0.4) + (ml * 100 * 0.4) + (behavioral * 100 * 0.2)
    return min(100.0, combined)


def determine_action(scores: ScoreData, is_anomaly: bool, behavioral_score: float) -> tuple[str, List[str], str]:
    """
    Determine action based on scores
    
    Returns (action, tags, reason)
    """
    tags = []
    
    # High ModSecurity score = block
    if scores.modsecurity >= 90:
        return "block", ["signature_match", "high_threat"], "High ModSecurity score"
    
    # Combined analysis for POI tagging
    if scores.combined >= 75:
        tags.append("poi")
        tags.append("high_combined_score")
        if is_anomaly:
            tags.append("ml_anomaly")
        if behavioral_score > 0.7:
            tags.append("behavioral_anomaly")
        return "tag_poi", tags, f"Combined score {scores.combined:.1f} exceeds threshold"
    
    if is_anomaly and scores.ml_anomaly >= 0.75:
        tags.append("poi")
        tags.append("ml_high_confidence")
        return "tag_poi", tags, "ML anomaly detection triggered"
    
    return "allow", ["normal"], "No threats detected"


def emit_poi_event(req: InspectRequest, scores: ScoreData, tags: List[str]) -> str:
    """
    Emit POI tagged event to message bus
    
    Returns event_id
    """
    event = POITaggedEvent(
        source="gatekeeper",
        session_id=req.session_id,
        client_ip=req.client_ip,
        request=RequestData(
            method=req.method,
            url=req.url,
            headers=req.headers,
            body=req.body,
            query_params=req.query_params
        ),
        tags=tags,
        scores=scores,
        geoip=GeoIPData(country="XX")  # In production: real GeoIP lookup
    )
    
    # In production: publish to Kafka/RabbitMQ
    print(f"[EVENT] POI_TAGGED: {event.event_id} - Session: {req.session_id}")
    
    # Save to file for demo (in production: use message broker)
    events_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'events')
    os.makedirs(events_dir, exist_ok=True)
    
    event_file = os.path.join(events_dir, f"{event.event_id}.json")
    with open(event_file, 'w') as f:
        f.write(event.model_dump_json(indent=2))
    
    return event.event_id


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
