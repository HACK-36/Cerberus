"""
Labyrinth - High-Interaction Honeypot Application
Realistic decoy application that captures attacker interactions
"""
from fastapi import FastAPI, Request, Response, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
import sys
import os
import time
from datetime import datetime
import json
import re

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from labyrinth.decoy_gen.data_generator import get_generator
from shared.events.schemas import PayloadCapturedEvent, RequestData, PayloadData
from shared.utils.metrics_router import router as metrics_router
from shared.utils.metrics import track_request_metrics
from labyrinth.capture.session_tracker import get_session_tracker
from shared.evidence.models import EvidencePointer

app = FastAPI(
    title="ACME Corp Internal Portal",  # Fake company name
    description="Internal business application",
    version="2.3.1"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include metrics router
app.include_router(metrics_router)

# Generate decoy data
generator = get_generator()
FAKE_USERS = generator.generate_users(100)
FAKE_DOCUMENTS = generator.generate_documents(50)
FAKE_API_KEYS = generator.generate_api_keys(20)
FAKE_TRANSACTIONS = generator.generate_transactions(200)

# Capture storage
EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'captures')
os.makedirs(EVIDENCE_DIR, exist_ok=True)

# Evidence session tracker
session_tracker = get_session_tracker()


# Models

class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    name: str
    email: str
    role: str = "user"


class FinalizeSessionRequest(BaseModel):
    session_id: Optional[str] = None


# Middleware for request capture

@app.middleware("http")
async def capture_middleware(request: Request, call_next):
    """Capture all requests for analysis"""
    start_time = time.time()
    # Read request body
    body_bytes = await request.body()
    body_str = body_bytes.decode('utf-8', errors='ignore')
    
    # Create capture record
    capture = {
        "timestamp": datetime.utcnow().isoformat(),
        "method": request.method,
        "url": str(request.url),
        "path": request.url.path,
        "query_params": dict(request.query_params),
        "headers": dict(request.headers),
        "body": body_str,
        "client_ip": request.client.host,
        "session": request.headers.get("X-Session-Id")
    }
    session_id = capture["session"] or request.headers.get("X-Session-Fingerprint") or capture["client_ip"] or "unknown"
    capture["session"] = session_id
    user_agent = capture["headers"].get("user-agent", "unknown")
    event_id = f"evt_{int(time.time())}_{session_id[:8]}"
    builder = session_tracker.get_or_create_session(
        session_id=session_id,
        event_id=event_id,
        attacker_ip=capture["client_ip"],
        user_agent=user_agent
    )
    
    # Extract potential attack payloads
    payloads = extract_payloads(capture)
    
    # Save capture
    capture_id = save_capture(capture, payloads)
    
    # Emit event if payloads detected
    if payloads:
        emit_payload_event(capture, payloads, capture_id)
    
    # Process request
    response = await call_next(request)

    duration_ms = (time.time() - start_time) * 1000
    response_status = response.status_code
    response_headers = dict(response.headers)
    response_body = ""
    if hasattr(response, "body") and response.body is not None:
        try:
            response_body = response.body.decode('utf-8', errors='ignore')[:10000]
        except AttributeError:
            pass

    try:
        builder.add_har_entry(
            method=capture["method"],
            url=capture["url"],
            request_headers=capture["headers"],
            request_body=capture["body"],
            response_status=response_status,
            response_headers=response_headers,
            response_body=response_body,
            start_time=datetime.utcnow(),
            duration_ms=duration_ms
        )
        for payload in payloads:
            builder.add_payload(
                payload_type=payload.type,
                payload_value=payload.value,
                location=payload.location,
                confidence=payload.confidence,
                save_as_file=len(payload.value) > 100
            )
            builder.add_tag(payload.type)
    finally:
        session_tracker.cleanup_expired_sessions()

    return response


# Decoy endpoints

@app.get("/", response_class=HTMLResponse)
async def index():
    """Fake home page"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>ACME Corp - Internal Portal</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .header { background: #003366; color: white; padding: 20px; }
            .nav { margin: 20px 0; }
            .nav a { margin-right: 20px; color: #0066cc; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>ACME Corporation</h1>
            <p>Internal Business Portal</p>
        </div>
        <div class="nav">
            <a href="/login">Login</a>
            <a href="/admin">Admin Panel</a>
            <a href="/api/v1/users">API</a>
            <a href="/docs">API Docs</a>
        </div>
        <p>Welcome to the ACME Corp internal portal. Please login to continue.</p>
        <p><small>Version 2.3.1 | &copy; 2024 ACME Corp</small></p>
    </body>
    </html>
    """


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    """Fake login page"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - ACME Corp</title>
        <style>
            body { font-family: Arial; max-width: 400px; margin: 100px auto; }
            input { width: 100%; padding: 10px; margin: 10px 0; }
            button { width: 100%; padding: 12px; background: #003366; color: white; border: none; cursor: pointer; }
        </style>
    </head>
    <body>
        <h2>ACME Corp Login</h2>
        <form method="POST" action="/api/v1/auth/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <p><small>Forgot password? <a href="/reset">Reset here</a></small></p>
    </body>
    </html>
    """


@app.post("/api/v1/auth/login")
async def fake_login(req: LoginRequest):
    """Fake login endpoint - always succeeds to engage attacker"""
    # Simulate successful login
    return {
        "status": "success",
        "message": "Login successful",
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIFVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.FakeTokenForHoneypot",
        "user": {
            "id": "USR-10001",
            "username": req.username,
            "role": "admin",  # Make them think they're admin
            "email": f"{req.username}@acmecorp.internal"
        }
    }


@app.get("/api/v1/users")
@track_request_metrics("labyrinth", "/api/v1/users", "GET")
async def get_users(limit: int = 10, role: Optional[str] = None):
    """Fake users API - returns synthetic data"""
    users = FAKE_USERS[:limit]
    
    if role:
        users = [u for u in users if u["role"] == role]
    
    return {
        "count": len(users),
        "users": users
    }


@app.get("/api/v1/users/{user_id}")
@track_request_metrics("labyrinth", "/api/v1/users/{user_id}", "GET")
async def get_user(user_id: str):
    """Get specific user"""
    for user in FAKE_USERS:
        if user["id"] == user_id:
            return user
    
    raise HTTPException(status_code=404, detail="User not found")


@app.post("/api/v1/users")
@track_request_metrics("labyrinth", "/api/v1/users", "POST")
async def create_user(req: CreateUserRequest):
    """Fake user creation"""
    new_user = {
        "id": f"USR-{len(FAKE_USERS) + 10000}",
        "name": req.name,
        "email": req.email,
        "role": req.role,
        "created_at": datetime.utcnow().isoformat()
    }
    
    return {
        "status": "success",
        "message": "User created",
        "user": new_user
    }


@app.get("/api/v1/documents")
@track_request_metrics("labyrinth", "/api/v1/documents", "GET")
async def get_documents():
    """Fake documents API"""
    return {
        "count": len(FAKE_DOCUMENTS),
        "documents": FAKE_DOCUMENTS
    }


@app.get("/api/v1/documents/{doc_id}/download")
@track_request_metrics("labyrinth", "/api/v1/documents/{doc_id}/download", "GET")
async def download_document(doc_id: str):
    """Fake document download"""
    # Return fake PDF content
    return Response(
        content=b"%PDF-1.4\n%FAKE DOCUMENT\nThis is a decoy file.\n",
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=document_{doc_id}.pdf"}
    )


@app.post("/api/v1/upload")
@track_request_metrics("labyrinth", "/api/v1/upload", "POST")
async def upload_file(file: UploadFile = File(...)):
    """File upload endpoint - captures uploaded files"""
    # Read file content
    content = await file.read()
    
    # Save uploaded file for analysis
    upload_dir = os.path.join(EVIDENCE_DIR, 'uploads')
    os.makedirs(upload_dir, exist_ok=True)
    
    filename = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
    filepath = os.path.join(upload_dir, filename)
    
    with open(filepath, 'wb') as f:
        f.write(content)
    
    print(f"[LABYRINTH] File uploaded: {filename} ({len(content)} bytes)")
    
    return {
        "status": "success",
        "message": "File uploaded successfully",
        "filename": file.filename,
        "size": len(content),
        "stored_as": filename
    }


@app.get("/admin", response_class=HTMLResponse)
@track_request_metrics("labyrinth", "/admin", "GET")
async def admin_panel():
    """Fake admin panel"""
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Admin Panel - ACME Corp</title></head>
    <body style="font-family: Arial; margin: 40px;">
        <h1>Admin Control Panel</h1>
        <h3>Quick Actions</h3>
        <ul>
            <li><a href="/admin/users">Manage Users</a></li>
            <li><a href="/admin/keys">API Keys</a></li>
            <li><a href="/admin/config">System Config</a></li>
            <li><a href="/admin/database">Database Console</a></li>
        </ul>
        <hr>
        <p><em>Admin access granted</em></p>
    </body>
    </html>
    """


@app.get("/admin/config")
@track_request_metrics("labyrinth", "/admin/config", "GET")
async def admin_config():
    """Fake config endpoint - exposes fake credentials"""
    return {
        "status": "success",
        "config": {
            "database": generator.generate_database_config(),
            "aws": generator.generate_aws_credentials(),
            "admin_users": generator.generate_admin_credentials(),
            "api_keys": FAKE_API_KEYS[:5]
        }
    }


@app.get("/.env")
@track_request_metrics("labyrinth", "/.env", "GET")
async def fake_env_file():
    """Fake .env file disclosure"""
    env_content = """# ACME Corp Configuration (FAKE)
DATABASE_URL=postgresql://admin:P@ssw0rd123@db.internal:5432/prod
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
REDIS_URL=redis://admin:secret@redis.internal:6379
SECRET_KEY=super-secret-key-do-not-share
"""
    return Response(content=env_content, media_type="text/plain")


@app.get("/health")
@track_request_metrics("labyrinth", "/health", "GET")
async def health():
    """Health check"""
    return {
        "status": "healthy",
        "service": "labyrinth",
        "version": "2.3.1",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/internal/sessions")
async def list_sessions():
    """List active evidence collection sessions (internal use)"""
    session_ids = session_tracker.list_session_ids()
    return {
        "active_count": len(session_ids),
        "sessions": session_ids
    }


@app.post("/internal/finalize-session")
async def finalize_session_endpoint(req: FinalizeSessionRequest):
    """Finalize a session and trigger evidence upload"""
    session_id = req.session_id
    if not session_id:
        return JSONResponse(
            status_code=400,
            content={"detail": "session_id is required"}
        )

    pointer: Optional[EvidencePointer] = session_tracker.finalize_session(session_id)
    if not pointer:
        return JSONResponse(
            status_code=404,
            content={"detail": f"Session '{session_id}' not found"}
        )

    return {
        "session_id": session_id,
        "pointer": pointer.model_dump()
    }


# Helper functions

def extract_payloads(capture: Dict) -> List[PayloadData]:
    """Extract attack payloads from captured request"""
    payloads = []
    
    combined_text = f"{capture['url']} {capture['body']} {json.dumps(capture['headers'])}"
    
    # SQL Injection patterns
    sql_patterns = [
        r"(\'\s*(OR|AND)\s*\'?\d*\'?\s*=\s*\'?\d*)",  # ' OR '1'='1
        r"(UNION\s+SELECT)",
        r"(;\s*(DROP|DELETE|INSERT|UPDATE)\s+)",
        r"(--|\#|\/\*)",  # SQL comments
    ]
    
    for pattern in sql_patterns:
        matches = re.findall(pattern, combined_text, re.IGNORECASE)
        if matches:
            payloads.append(PayloadData(
                type="sql_injection",
                value=str(matches[0])[:200],
                location=f"request",
                confidence=0.85
            ))
            break
    
    # XSS patterns
    xss_patterns = [
        r"<script[^>]*>",
        r"javascript:",
        r"on\w+\s*=",  # onerror=, onload=, etc.
    ]
    
    for pattern in xss_patterns:
        if re.search(pattern, combined_text, re.IGNORECASE):
            match = re.search(pattern, combined_text, re.IGNORECASE)
            payloads.append(PayloadData(
                type="xss",
                value=match.group(0)[:200],
                location="request",
                confidence=0.80
            ))
            break
    
    # Command Injection
    cmd_patterns = [
        r"[;&|]\s*(cat|ls|whoami|wget|curl|bash|sh|nc)",
        r"\$\((.*?)\)",  # Command substitution
    ]
    
    for pattern in cmd_patterns:
        matches = re.findall(pattern, combined_text, re.IGNORECASE)
        if matches:
            payloads.append(PayloadData(
                type="command_injection",
                value=str(matches[0])[:200],
                location="request",
                confidence=0.75
            ))
            break
    
    # Path Traversal
    if re.search(r"(\.\.\/|\.\.\\|%2e%2e)", combined_text, re.IGNORECASE):
        payloads.append(PayloadData(
            type="path_traversal",
            value=combined_text[:200],
            location="url",
            confidence=0.90
        ))
    
    return payloads


def save_capture(capture: Dict, payloads: List[PayloadData]) -> str:
    """Save capture to evidence storage"""
    capture_id = f"cap_{datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')}"
    
    capture_data = {
        "capture_id": capture_id,
        **capture,
        "payloads": [p.model_dump() for p in payloads]
    }
    
    filepath = os.path.join(EVIDENCE_DIR, f"{capture_id}.json")
    with open(filepath, 'w') as f:
        json.dump(capture_data, f, indent=2)
    
    return capture_id


def emit_payload_event(capture: Dict, payloads: List[PayloadData], capture_id: str):
    """Emit payload captured event"""
    event = PayloadCapturedEvent(
        source="labyrinth",
        session_id=capture.get("session", "unknown"),
        client_ip=capture["client_ip"],
        capture_id=capture_id,
        request=RequestData(
            method=capture["method"],
            url=capture["url"],
            headers=capture["headers"],
            body=capture["body"],
            query_params=capture["query_params"]
        ),
        extracted_payloads=payloads,
        evidence_url=f"file://{EVIDENCE_DIR}/{capture_id}.json"
    )
    
    # Save event
    events_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'events')
    os.makedirs(events_dir, exist_ok=True)
    
    event_file = os.path.join(events_dir, f"{event.event_id}.json")
    with open(event_file, 'w') as f:
        f.write(event.model_dump_json(indent=2))
    
    print(f"[LABYRINTH] Payload captured: {capture_id} - {len(payloads)} payloads")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
