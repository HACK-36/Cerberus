"""
HAR Recording Middleware for Labyrinth
Captures complete request/response pairs in HAR format
"""
import time
from datetime import datetime
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from typing import Callable
import logging

from labyrinth.capture.session_tracker import get_session_tracker
from shared.events.schemas import PayloadData

logger = logging.getLogger(__name__)


class HARRecorderMiddleware(BaseHTTPMiddleware):
    """
    Middleware that records HTTP traffic in HAR format
    
    For each request/response:
    1. Extracts request details (method, URL, headers, body)
    2. Captures response details (status, headers, body)
    3. Records timing information
    4. Adds entry to session's HAR log via EvidenceBuilder
    """
    
    def __init__(self, app: ASGIApp, payload_extractor: Callable = None):
        """
        Initialize HAR recorder middleware
        
        Args:
            app: ASGI application
            payload_extractor: Optional function to extract attack payloads
        """
        super().__init__(app)
        self.payload_extractor = payload_extractor
        self.session_tracker = get_session_tracker()
    
    async def dispatch(self, request: Request, call_next):
        """
        Process request and capture HAR entry
        
        Args:
            request: Incoming request
            call_next: Next middleware/endpoint
            
        Returns:
            Response
        """
        # Start timing
        start_time = time.time()
        start_datetime = datetime.utcnow()
        
        # Extract request details
        request_body = await self._read_body(request)
        request_method = request.method
        request_url = str(request.url)
        request_headers = dict(request.headers)
        
        # Get session info
        session_id = request_headers.get("x-session-id", request_headers.get("x-session-fingerprint", "unknown"))
        attacker_ip = request.client.host if request.client else "unknown"
        user_agent = request_headers.get("user-agent", "unknown")
        
        # Generate event ID for this capture
        event_id = f"evt_{int(time.time())}_{session_id[:8]}"
        
        # Get or create evidence builder for this session
        builder = self.session_tracker.get_or_create_session(
            session_id=session_id,
            event_id=event_id,
            attacker_ip=attacker_ip,
            user_agent=user_agent
        )
        
        # Extract attack payloads if extractor provided
        if self.payload_extractor and request_body:
            try:
                payloads = self.payload_extractor(request)
                for payload in payloads:
                    builder.add_payload(
                        payload_type=payload.type,
                        payload_value=payload.value,
                        location=payload.location,
                        confidence=payload.confidence,
                        save_as_file=len(payload.value) > 100  # Save large payloads as files
                    )
                    
                    # Add tags based on payload types
                    builder.add_tag(payload.type)
            except Exception as e:
                logger.error(f"Failed to extract payloads: {e}")
        
        # Process request
        try:
            response = await call_next(request)
        except Exception as e:
            logger.error(f"Error processing request: {e}")
            # Create error response
            response = Response(
                content=str(e),
                status_code=500,
                headers={"Content-Type": "text/plain"}
            )
        
        # End timing
        end_time = time.time()
        duration_ms = (end_time - start_time) * 1000
        
        # Capture response details
        response_status = response.status_code
        response_headers = dict(response.headers)
        
        # Read response body (if small enough)
        response_body = ""
        try:
            if hasattr(response, 'body'):
                response_body = response.body.decode('utf-8', errors='ignore')[:10000]  # Limit to 10KB
        except Exception as e:
            logger.debug(f"Could not read response body: {e}")
        
        # Add HAR entry to evidence builder
        try:
            builder.add_har_entry(
                method=request_method,
                url=request_url,
                request_headers=request_headers,
                request_body=request_body,
                response_status=response_status,
                response_headers=response_headers,
                response_body=response_body,
                start_time=start_datetime,
                duration_ms=duration_ms
            )
        except Exception as e:
            logger.error(f"Failed to add HAR entry: {e}")
        
        return response
    
    async def _read_body(self, request: Request) -> str:
        """
        Read request body safely
        
        Args:
            request: Request object
            
        Returns:
            Body as string
        """
        try:
            body_bytes = await request.body()
            return body_bytes.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"Could not read request body: {e}")
            return ""


def extract_payloads_from_request(request: Request) -> list:
    """
    Extract attack payloads from request
    
    This is a helper function that can be passed to HARRecorderMiddleware
    
    Args:
        request: Request to analyze
        
    Returns:
        List of PayloadData objects
    """
    import re
    
    payloads = []
    
    # Get all searchable text
    url = str(request.url)
    headers_str = str(dict(request.headers))
    
    # Try to get body
    body = ""
    # Note: body is already read in middleware, would need to cache it
    
    combined_text = f"{url} {headers_str} {body}"
    
    # SQL Injection patterns
    sql_patterns = [
        (r"('\s*(OR|AND)\s*'?\d*'?\s*=\s*'?\d*)", "sql_injection"),
        (r"(UNION\s+SELECT)", "sql_injection"),
        (r"(;\s*(DROP|DELETE|INSERT|UPDATE)\s+)", "sql_injection"),
    ]
    
    for pattern, payload_type in sql_patterns:
        matches = re.findall(pattern, combined_text, re.IGNORECASE)
        if matches:
            match_str = str(matches[0])[:200]
            payloads.append(PayloadData(
                type=payload_type,
                value=match_str,
                location="request",
                confidence=0.85
            ))
            break
    
    # XSS patterns
    xss_patterns = [
        (r"<script[^>]*>", "xss"),
        (r"javascript:", "xss"),
        (r"on\w+\s*=", "xss"),
    ]
    
    for pattern, payload_type in xss_patterns:
        if re.search(pattern, combined_text, re.IGNORECASE):
            match = re.search(pattern, combined_text, re.IGNORECASE)
            payloads.append(PayloadData(
                type=payload_type,
                value=match.group(0)[:200],
                location="request",
                confidence=0.80
            ))
            break
    
    # Command Injection
    cmd_patterns = [
        (r"[;&|]\s*(cat|ls|whoami|wget|curl|bash|sh|nc)", "command_injection"),
    ]
    
    for pattern, payload_type in cmd_patterns:
        matches = re.findall(pattern, combined_text, re.IGNORECASE)
        if matches:
            payloads.append(PayloadData(
                type=payload_type,
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
