"""
Request Capture Agent for Labyrinth
Captures and stores raw requests for Sentinel analysis
"""
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
import json
import os
from datetime import datetime
from typing import Dict
import hashlib


class RequestCaptureMiddleware(BaseHTTPMiddleware):
    """Middleware to capture all requests"""

    def __init__(self, app, capture_dir: str = "labyrinth/capture"):
        super().__init__(app)
        self.capture_dir = capture_dir
        os.makedirs(capture_dir, exist_ok=True)

    async def dispatch(self, request: Request, call_next):
        # Capture request before processing
        request_data = await self._capture_request(request)

        # Process the request
        response = await call_next(request)

        # Save capture after processing
        await self._save_capture(request_data, response)

        return response

    async def _capture_request(self, request: Request) -> Dict:
        """Capture request details"""
        body = await request.body()

        capture = {
            "timestamp": datetime.utcnow().isoformat(),
            "method": request.method,
            "url": str(request.url),
            "path": request.url.path,
            "query_params": dict(request.query_params),
            "headers": dict(request.headers),
            "client_ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", ""),
            "body": body.decode("utf-8", errors="ignore") if body else "",
            "session_id": request.cookies.get("session", ""),
            "request_id": hashlib.md5(f"{request.url}{datetime.utcnow()}".encode()).hexdigest()[:16]
        }

        return capture

    async def _save_capture(self, request_data: Dict, response):
        """Save capture to file"""
        filename = f"{self.capture_dir}/{request_data['request_id']}.json"

        capture_data = {
            "request": request_data,
            "response": {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "timestamp": datetime.utcnow().isoformat()
            }
        }

        with open(filename, 'w') as f:
            json.dump(capture_data, f, indent=2)


# Alternative capture agent (if not using middleware)
class CaptureAgent:
    """Standalone capture agent"""

    def __init__(self, capture_dir: str = "labyrinth/capture"):
        self.capture_dir = capture_dir
        os.makedirs(capture_dir, exist_ok=True)

    def capture_request(self, request: Request) -> str:
        """Capture a request and return capture ID"""
        import asyncio
        return asyncio.run(self._async_capture_request(request))

    async def _async_capture_request(self, request: Request) -> str:
        """Async capture"""
        body = await request.body()

        capture = {
            "timestamp": datetime.utcnow().isoformat(),
            "method": request.method,
            "url": str(request.url),
            "path": request.url.path,
            "query_params": dict(request.query_params),
            "headers": dict(request.headers),
            "client_ip": request.client.host if request.client else "unknown",
            "body": body.decode("utf-8", errors="ignore") if body else "",
            "session_id": request.cookies.get("session", ""),
        }

        request_id = hashlib.md5(f"{request.url}{datetime.utcnow()}".encode()).hexdigest()[:16]
        filename = f"{self.capture_dir}/{request_id}.json"

        with open(filename, 'w') as f:
            json.dump(capture, f, indent=2)

        return request_id

    def get_captures(self) -> list:
        """Get list of capture files"""
        if not os.path.exists(self.capture_dir):
            return []

        return [f for f in os.listdir(self.capture_dir) if f.endswith('.json')]

    def get_capture(self, capture_id: str) -> Dict:
        """Get capture data"""
        filename = f"{self.capture_dir}/{capture_id}.json"
        if not os.path.exists(filename):
            return {}

        with open(filename, 'r') as f:
            return json.load(f)
