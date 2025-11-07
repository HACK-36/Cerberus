"""
Switch API Service
Manages session pinning and routing between production and Labyrinth
"""
from fastapi import FastAPI, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, List, Literal, Optional
from datetime import datetime, timedelta
import hashlib
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.events.schemas import SessionPinnedEvent

app = FastAPI(
    title="Cerberus Switch API",
    description="Session routing and pinning management",
    version="1.0.0"
)

security = HTTPBearer()

# Session pin storage (in production: use Redis with TTL)
pinned_sessions: Dict[str, Dict] = {}

# Configuration
PIN_DURATION_HOURS = 24
PRODUCTION_BACKEND = "http://production-backend:8080"
LABYRINTH_BACKEND = "http://labyrinth:8080"


class PinSessionRequest(BaseModel):
    """Request to pin a session to Labyrinth"""
    session_id: str
    client_ip: str
    reason: str
    duration_hours: int = PIN_DURATION_HOURS
    metadata: Dict = {}


class PinSessionResponse(BaseModel):
    """Response after pinning session"""
    session_id: str
    fingerprint: str
    target: str
    pinned_until: str
    event_id: str


class SessionInfo(BaseModel):
    """Session pinning information"""
    session_id: str
    fingerprint: str
    target: Literal["production", "labyrinth"]
    pinned_at: str
    pinned_until: str
    reason: str
    metadata: Dict


class RouteRequest(BaseModel):
    """Request for routing decision"""
    session_id: Optional[str] = None
    client_ip: str
    user_agent: str
    cookies: Dict[str, str] = {}
    jwt_token: Optional[str] = None


class RouteResponse(BaseModel):
    """Routing decision"""
    target: Literal["production", "labyrinth"]
    backend_url: str
    preserve_host: bool = True
    additional_headers: Dict[str, str] = {}


@app.get("/health")
async def health_check():
    """Health check"""
    return {
        "status": "healthy",
        "service": "switch",
        "timestamp": datetime.utcnow().isoformat(),
        "pinned_sessions": len(pinned_sessions)
    }


@app.post("/api/v1/switch/pin", response_model=PinSessionResponse)
async def pin_session(
    req: PinSessionRequest,
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    """
    Pin a session to the Labyrinth
    
    This is called when Gatekeeper tags a session as POI
    """
    # Generate session fingerprint
    fingerprint = generate_fingerprint(req.session_id, req.client_ip)
    
    # Calculate expiration
    pinned_until = datetime.utcnow() + timedelta(hours=req.duration_hours)
    
    # Store pin
    pinned_sessions[fingerprint] = {
        "session_id": req.session_id,
        "fingerprint": fingerprint,
        "target": "labyrinth",
        "pinned_at": datetime.utcnow().isoformat(),
        "pinned_until": pinned_until.isoformat(),
        "reason": req.reason,
        "metadata": req.metadata
    }
    
    # Emit event
    event = SessionPinnedEvent(
        source="switch",
        session_id=req.session_id,
        client_ip=req.client_ip,
        fingerprint=fingerprint,
        target="labyrinth",
        pin_duration_hours=req.duration_hours,
        reason=req.reason
    )
    
    # Save event (in production: publish to message bus)
    _save_event(event)
    
    print(f"[SWITCH] Session pinned: {req.session_id} -> Labyrinth (until {pinned_until})")
    
    return PinSessionResponse(
        session_id=req.session_id,
        fingerprint=fingerprint,
        target="labyrinth",
        pinned_until=pinned_until.isoformat(),
        event_id=event.event_id
    )


@app.post("/api/v1/switch/route", response_model=RouteResponse)
async def get_route(req: RouteRequest):
    """
    Get routing decision for a request
    
    Called by Envoy/NGINX for each request to determine target backend
    """
    # Generate fingerprint from request
    fingerprint = _extract_fingerprint(req)
    
    # Check if session is pinned
    if fingerprint in pinned_sessions:
        pin_info = pinned_sessions[fingerprint]
        
        # Check if pin has expired
        pinned_until = datetime.fromisoformat(pin_info["pinned_until"])
        if datetime.utcnow() > pinned_until:
            # Pin expired, remove it
            del pinned_sessions[fingerprint]
            print(f"[SWITCH] Pin expired: {fingerprint}")
        else:
            # Route to Labyrinth
            return RouteResponse(
                target="labyrinth",
                backend_url=LABYRINTH_BACKEND,
                preserve_host=True,
                additional_headers={
                    "X-Cerberus-Routed": "labyrinth",
                    "X-Original-IP": req.client_ip,
                    "X-Session-Fingerprint": fingerprint
                }
            )
    
    # Default: route to production
    return RouteResponse(
        target="production",
        backend_url=PRODUCTION_BACKEND,
        preserve_host=True,
        additional_headers={}
    )


@app.get("/api/v1/switch/sessions", response_model=List[SessionInfo])
async def list_sessions():
    """List all pinned sessions"""
    sessions = []
    now = datetime.utcnow()
    
    # Clean expired sessions
    expired = []
    for fingerprint, info in pinned_sessions.items():
        pinned_until = datetime.fromisoformat(info["pinned_until"])
        if now > pinned_until:
            expired.append(fingerprint)
        else:
            sessions.append(SessionInfo(**info))
    
    for fp in expired:
        del pinned_sessions[fp]
    
    return sessions


@app.get("/api/v1/switch/sessions/{session_id}")
async def get_session(session_id: str):
    """Get info about a specific session"""
    for info in pinned_sessions.values():
        if info["session_id"] == session_id:
            return SessionInfo(**info)
    
    raise HTTPException(status_code=404, detail="Session not found")


@app.delete("/api/v1/switch/pin/{session_id}")
async def unpin_session(
    session_id: str,
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    """
    Unpin a session (return to production routing)
    """
    # Find and remove pin
    removed = False
    for fingerprint, info in list(pinned_sessions.items()):
        if info["session_id"] == session_id:
            del pinned_sessions[fingerprint]
            removed = True
            print(f"[SWITCH] Session unpinned: {session_id}")
    
    if not removed:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {"session_id": session_id, "status": "unpinned"}


@app.get("/api/v1/switch/stats")
async def get_stats():
    """Get Switch statistics"""
    now = datetime.utcnow()
    active = sum(1 for info in pinned_sessions.values() 
                 if datetime.fromisoformat(info["pinned_until"]) > now)
    
    return {
        "total_pinned": len(pinned_sessions),
        "active_pins": active,
        "production_backend": PRODUCTION_BACKEND,
        "labyrinth_backend": LABYRINTH_BACKEND
    }


# Helper functions

def generate_fingerprint(session_id: str, client_ip: str) -> str:
    """Generate consistent fingerprint for session"""
    data = f"{session_id}:{client_ip}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def _extract_fingerprint(req: RouteRequest) -> str:
    """
    Extract session fingerprint from request
    Priority: session_id > JWT > Cookie > IP+UA hash
    """
    # Primary: explicit session ID
    if req.session_id:
        return generate_fingerprint(req.session_id, req.client_ip)
    
    # Secondary: session cookie
    if 'session_id' in req.cookies:
        return generate_fingerprint(req.cookies['session_id'], req.client_ip)
    
    # Tertiary: JWT subject
    if req.jwt_token:
        # In production: parse JWT and extract sub claim
        jwt_hash = hashlib.sha256(req.jwt_token.encode()).hexdigest()[:16]
        return jwt_hash
    
    # Fallback: IP + User-Agent hash (less stable)
    data = f"{req.client_ip}:{req.user_agent}"
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def _save_event(event: SessionPinnedEvent):
    """Save event to storage"""
    events_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'events')
    os.makedirs(events_dir, exist_ok=True)
    
    event_file = os.path.join(events_dir, f"{event.event_id}.json")
    with open(event_file, 'w') as f:
        f.write(event.model_dump_json(indent=2))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
