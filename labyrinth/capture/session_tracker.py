"""
Session Tracker for Labyrinth
Tracks attacker sessions and coordinates evidence collection
"""
import time
from typing import Dict, Optional
from datetime import datetime
from threading import Lock
import logging

from shared.evidence.builder import EvidenceBuilder
from shared.evidence.models import EvidencePointer

logger = logging.getLogger(__name__)


class SessionTracker:
    """
    Tracks active attacker sessions and coordinates evidence building
    
    One tracker per session, collects requests/responses and
    builds evidence package on session end
    """
    
    def __init__(self):
        """Initialize session tracker"""
        self.sessions: Dict[str, EvidenceBuilder] = {}
        self.lock = Lock()
        self.session_timeouts: Dict[str, float] = {}
        self.timeout_seconds = 300  # 5 minutes of inactivity closes session
    
    def get_or_create_session(
        self,
        session_id: str,
        event_id: str,
        attacker_ip: str,
        user_agent: str
    ) -> EvidenceBuilder:
        """
        Get existing session builder or create new one
        
        Args:
            session_id: Session identifier
            event_id: Event ID for evidence package
            attacker_ip: Source IP
            user_agent: User-Agent header
            
        Returns:
            Evidence builder for this session
        """
        with self.lock:
            if session_id not in self.sessions:
                logger.info(f"Starting evidence collection for session {session_id}")
                self.sessions[session_id] = EvidenceBuilder(
                    event_id=event_id,
                    session_id=session_id,
                    attacker_ip=attacker_ip,
                    user_agent=user_agent
                )
            
            # Update last activity time
            self.session_timeouts[session_id] = time.time()
            
            return self.sessions[session_id]
    
    def finalize_session(self, session_id: str) -> Optional[EvidencePointer]:
        """
        Finalize session and upload evidence package
        
        Args:
            session_id: Session to finalize
            
        Returns:
            Evidence pointer if successful, None otherwise
        """
        with self.lock:
            builder = self.sessions.get(session_id)
            if not builder:
                logger.warning(f"No evidence builder found for session {session_id}")
                return None
            
            try:
                logger.info(f"Finalizing evidence package for session {session_id}")
                pointer = builder.build_and_upload()
                
                # Cleanup
                del self.sessions[session_id]
                if session_id in self.session_timeouts:
                    del self.session_timeouts[session_id]
                
                logger.info(f"Evidence package uploaded: {pointer.location}")
                return pointer
            
            except Exception as e:
                logger.error(f"Failed to finalize session {session_id}: {e}")
                return None
    
    def cleanup_expired_sessions(self):
        """Cleanup sessions that have exceeded timeout"""
        current_time = time.time()
        expired = []
        
        with self.lock:
            for session_id, last_activity in self.session_timeouts.items():
                if current_time - last_activity > self.timeout_seconds:
                    expired.append(session_id)
        
        for session_id in expired:
            logger.info(f"Session {session_id} expired, finalizing...")
            self.finalize_session(session_id)
    
    def get_active_sessions(self) -> int:
        """Get count of active sessions"""
        with self.lock:
            return len(self.sessions)

    def list_session_ids(self) -> list:
        """Get list of active session identifiers"""
        with self.lock:
            return list(self.sessions.keys())


# Global session tracker instance
_session_tracker: Optional[SessionTracker] = None


def get_session_tracker() -> SessionTracker:
    """Get singleton session tracker"""
    global _session_tracker
    if _session_tracker is None:
        _session_tracker = SessionTracker()
    return _session_tracker
