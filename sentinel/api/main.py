"""
Sentinel API - Threat Twin AI Analysis Engine
Orchestrates profiling, simulation, rule generation, and policy decisions
"""
from fastapi import FastAPI, HTTPException, Security, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Dict, Optional, Literal
import sys
import os
from datetime import datetime
import json
import requests

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from sentinel.profiler.behavioral_profiler import BehavioralProfiler
from sentinel.simulator.payload_simulator import PayloadSimulator
from sentinel.rule_gen.rule_generator import RuleGenerator
from shared.events.schemas import (
    WAFRule, SimulationCompleteEvent, RuleGeneratedEvent,
    SimulationResult, AttackerProfile
)

app = FastAPI(
    title="Cerberus Sentinel API",
    description="AI-driven threat analysis and response",
    version="1.0.0"
)

security = HTTPBearer()

# Initialize components
profiler = BehavioralProfiler()
simulator = PayloadSimulator()
rule_generator = RuleGenerator()

# Storage (in production: use PostgreSQL/Redis)
simulation_results: Dict[str, Dict] = {}
generated_rules: Dict[str, WAFRule] = {}
attacker_profiles: Dict[str, Dict] = {}

# Configuration
GATEKEEPER_API_URL = os.getenv("GATEKEEPER_API_URL", "http://gatekeeper:8000")
AUTO_APPLY_THRESHOLD = 0.90
REVIEW_THRESHOLD = 0.70


# Models

class SimulateRequest(BaseModel):
    """Request to simulate a payload"""
    payload: Dict
    shadow_app_ref: str = "main"
    metadata: Dict = {}


class SimulateResponse(BaseModel):
    """Simulation job response"""
    job_id: str
    status: Literal["queued", "running", "completed", "failed"]
    message: str


class ProfileRequest(BaseModel):
    """Request to profile a session"""
    session_id: str
    captures: List[Dict]


class RuleProposeRequest(BaseModel):
    """Request to propose a rule"""
    payload: Dict
    sim_result: Dict
    profile: Optional[Dict] = None


class RuleApplyRequest(BaseModel):
    """Request to apply a rule"""
    rule_id: str
    force: bool = False


class PolicyDecision(BaseModel):
    """Policy orchestrator decision"""
    decision: Literal["auto_applied", "pending_review", "logged_only"]
    reason: str
    rule_id: str
    confidence: float


# API Endpoints

@app.get("/health")
async def health_check():
    """Health check"""
    return {
        "status": "healthy",
        "service": "sentinel",
        "timestamp": datetime.utcnow().isoformat(),
        "simulations": len(simulation_results),
        "rules_generated": len(generated_rules),
        "profiles": len(attacker_profiles)
    }


@app.post("/api/v1/sentinel/profile")
async def profile_session(req: ProfileRequest):
    """
    Profile an attacker session
    
    Analyzes behavior and maps to MITRE ATT&CK TTPs
    """
    print(f"[SENTINEL] Profiling session: {req.session_id}")
    
    # Analyze session
    profile = profiler.analyze_session(req.captures)
    
    # Store profile
    attacker_profiles[req.session_id] = profile
    
    print(f"[SENTINEL] Profile complete: {profile['intent']} (sophistication={profile['sophistication_score']:.1f})")
    
    return {
        "session_id": req.session_id,
        "profile": profile
    }


@app.post("/api/v1/sentinel/simulate", response_model=SimulateResponse)
async def simulate_payload(
    req: SimulateRequest,
    background_tasks: BackgroundTasks
):
    """
    Simulate a payload in sandbox (async)
    
    Returns job_id immediately, simulation runs in background
    """
    job_id = f"sim_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    
    # Initialize job
    simulation_results[job_id] = {
        "status": "queued",
        "payload": req.payload,
        "started_at": datetime.utcnow().isoformat()
    }
    
    # Run simulation in background
    background_tasks.add_task(
        run_simulation,
        job_id,
        req.payload,
        req.shadow_app_ref,
        req.metadata
    )
    
    print(f"[SENTINEL] Simulation queued: {job_id}")
    
    return SimulateResponse(
        job_id=job_id,
        status="queued",
        message="Simulation queued for execution"
    )


@app.get("/api/v1/sentinel/sim-result/{job_id}")
async def get_simulation_result(job_id: str):
    """Get simulation result"""
    if job_id not in simulation_results:
        raise HTTPException(status_code=404, detail="Simulation not found")
    
    return simulation_results[job_id]


@app.post("/api/v1/sentinel/rule-propose")
async def propose_rule(req: RuleProposeRequest):
    """
    Propose a WAF rule based on simulation result
    
    Does not apply the rule, only generates and returns it
    """
    print(f"[SENTINEL] Proposing rule for {req.payload.get('type')} payload")
    
    # Generate rule
    rule = rule_generator.generate_rule(
        req.payload,
        req.sim_result,
        req.profile
    )
    
    if not rule:
        raise HTTPException(
            status_code=400,
            detail="Cannot generate rule for this payload/result"
        )
    
    # Store proposed rule
    generated_rules[rule.rule_id] = rule
    
    return {
        "rule": rule.model_dump(),
        "message": "Rule proposed successfully",
        "recommendation": "auto_apply" if rule.confidence >= AUTO_APPLY_THRESHOLD else "manual_review"
    }


@app.post("/api/v1/sentinel/rule-apply", response_model=PolicyDecision)
async def apply_rule(
    req: RuleApplyRequest,
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    """
    Apply a rule (push to Gatekeeper)
    
    Policy orchestrator decides whether to auto-apply or queue for review
    """
    if req.rule_id not in generated_rules:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    rule = generated_rules[req.rule_id]
    
    # Policy decision
    decision = orchestrate_policy(rule, req.force)
    
    if decision["decision"] == "auto_applied":
        # Push to Gatekeeper
        success = push_rule_to_gatekeeper(rule)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to push rule to Gatekeeper")
        
        # Emit event
        emit_rule_generated_event(rule, "auto_applied")
        
        print(f"[SENTINEL] Rule auto-applied: {rule.rule_id}")
    
    elif decision["decision"] == "pending_review":
        print(f"[SENTINEL] Rule pending review: {rule.rule_id}")
        # In production: send to review queue / alert SOC
    
    else:
        print(f"[SENTINEL] Rule logged only: {rule.rule_id}")
    
    return PolicyDecision(**decision)


@app.get("/api/v1/sentinel/rules")
async def list_rules():
    """List all generated rules"""
    return {
        "rules": [r.model_dump() for r in generated_rules.values()],
        "count": len(generated_rules)
    }


@app.get("/api/v1/sentinel/profiles")
async def list_profiles():
    """List all attacker profiles"""
    return {
        "profiles": list(attacker_profiles.values()),
        "count": len(attacker_profiles)
    }


@app.get("/api/v1/sentinel/stats")
async def get_stats():
    """Get Sentinel statistics"""
    completed_sims = sum(1 for s in simulation_results.values() if s.get("status") == "completed")
    exploits_found = sum(1 for s in simulation_results.values() 
                         if s.get("result", {}).get("verdict") == "exploit_possible")
    
    return {
        "total_simulations": len(simulation_results),
        "completed_simulations": completed_sims,
        "exploits_detected": exploits_found,
        "rules_generated": len(generated_rules),
        "profiles_created": len(attacker_profiles),
        "auto_applied_rules": sum(1 for r in generated_rules.values() if r.confidence >= AUTO_APPLY_THRESHOLD)
    }


# Background tasks

def run_simulation(job_id: str, payload: Dict, shadow_ref: str, metadata: Dict):
    """Run simulation in background"""
    try:
        print(f"[SENTINEL] Starting simulation: {job_id}")
        
        simulation_results[job_id]["status"] = "running"
        
        # Run simulation
        result = simulator.simulate(payload, shadow_ref)
        
        # Update job
        simulation_results[job_id]["status"] = "completed"
        simulation_results[job_id]["result"] = result
        simulation_results[job_id]["completed_at"] = datetime.utcnow().isoformat()
        
        # Emit event
        emit_simulation_event(job_id, payload, result)
        
        print(f"[SENTINEL] Simulation completed: {job_id} - {result['verdict']}")
        
        # If exploit detected, auto-generate rule
        if result["verdict"] == "exploit_possible":
            auto_generate_rule(payload, result, metadata)
    
    except Exception as e:
        print(f"[SENTINEL] Simulation failed: {job_id} - {e}")
        simulation_results[job_id]["status"] = "failed"
        simulation_results[job_id]["error"] = str(e)


def auto_generate_rule(payload: Dict, sim_result: Dict, metadata: Dict):
    """Automatically generate and apply rule for high-confidence exploits"""
    try:
        # Get profile if available
        session_id = metadata.get("session_id")
        profile = attacker_profiles.get(session_id) if session_id else None
        
        # Generate rule
        rule = rule_generator.generate_rule(payload, sim_result, profile)
        
        if not rule:
            return
        
        generated_rules[rule.rule_id] = rule
        
        # Policy decision
        decision = orchestrate_policy(rule, force=False)
        
        if decision["decision"] == "auto_applied":
            push_rule_to_gatekeeper(rule)
            emit_rule_generated_event(rule, "auto_applied")
            print(f"[SENTINEL] Auto-generated and applied rule: {rule.rule_id}")
        else:
            emit_rule_generated_event(rule, decision["decision"])
            print(f"[SENTINEL] Auto-generated rule (pending review): {rule.rule_id}")
    
    except Exception as e:
        print(f"[SENTINEL] Failed to auto-generate rule: {e}")


# Helper functions

def orchestrate_policy(rule: WAFRule, force: bool = False) -> Dict:
    """
    Policy Orchestrator - Decide whether to auto-apply rule
    
    Returns decision dict with: decision, reason, rule_id, confidence
    """
    confidence = rule.confidence
    
    if force:
        return {
            "decision": "auto_applied",
            "reason": "Forced by administrator",
            "rule_id": rule.rule_id,
            "confidence": confidence
        }
    
    if confidence >= AUTO_APPLY_THRESHOLD:
        return {
            "decision": "auto_applied",
            "reason": f"High confidence ({confidence:.2f}) >= threshold ({AUTO_APPLY_THRESHOLD})",
            "rule_id": rule.rule_id,
            "confidence": confidence
        }
    
    elif confidence >= REVIEW_THRESHOLD:
        return {
            "decision": "pending_review",
            "reason": f"Medium confidence ({confidence:.2f}) requires manual review",
            "rule_id": rule.rule_id,
            "confidence": confidence
        }
    
    else:
        return {
            "decision": "logged_only",
            "reason": f"Low confidence ({confidence:.2f}) - logged for analysis",
            "rule_id": rule.rule_id,
            "confidence": confidence
        }


def push_rule_to_gatekeeper(rule: WAFRule) -> bool:
    """Push rule to Gatekeeper via API"""
    try:
        response = requests.post(
            f"{GATEKEEPER_API_URL}/api/v1/gatekeeper/rules",
            json={"rule": rule.model_dump()},
            headers={"Authorization": "Bearer sentinel-token"},  # In production: use real auth
            timeout=10
        )
        
        return response.status_code in [200, 201]
    
    except Exception as e:
        print(f"[SENTINEL] Failed to push rule to Gatekeeper: {e}")
        return False


def emit_simulation_event(job_id: str, payload: Dict, result: Dict):
    """Emit simulation complete event"""
    event = SimulationCompleteEvent(
        source="sentinel",
        session_id=result.get("session_id", "unknown"),
        client_ip="unknown",
        simulation_id=job_id,
        payload_id=payload.get("id", "unknown"),
        result=SimulationResult(
            verdict=result["verdict"],
            severity=result["severity"],
            attack_type=result["attack_type"],
            exploitation_evidence=str(result.get("evidence", {})),
            affected_resources=[],
            reproduction_steps=result.get("reproduction_steps", [])
        ),
        execution_time_ms=result.get("execution_time_ms", 0)
    )
    
    _save_event(event)


def emit_rule_generated_event(rule: WAFRule, action: str):
    """Emit rule generated event"""
    event = RuleGeneratedEvent(
        source="sentinel",
        session_id="unknown",
        client_ip="unknown",
        rule=rule,
        action=action,
        reason=f"Confidence: {rule.confidence:.2f}"
    )
    
    _save_event(event)


def _save_event(event):
    """Save event to storage"""
    events_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'events')
    os.makedirs(events_dir, exist_ok=True)
    
    event_file = os.path.join(events_dir, f"{event.event_id}.json")
    with open(event_file, 'w') as f:
        f.write(event.model_dump_json(indent=2))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
