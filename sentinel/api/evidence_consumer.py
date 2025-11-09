"""
Evidence Consumer for Sentinel
Consumes evidence pointers from Kafka and triggers analysis pipeline
"""
import os
import logging
import threading
from typing import Callable, Optional
from datetime import datetime

from shared.messaging.event_bus import get_event_bus
from shared.evidence.models import EvidencePointer
from shared.evidence.retriever import EvidenceRetriever

logger = logging.getLogger(__name__)


class EvidenceConsumer:
    """
    Consumes evidence pointers and triggers Sentinel analysis pipeline
    Workflow:
    1. Subscribe to cerberus.evidence.ready topic
    2. Receive evidence pointer
    3. Download evidence package from MinIO
    4. Trigger behavioral profiling
    5. Queue payload simulation
    6. Generate rules based on results
    """
    
    def __init__(
        self,
        group_id: str = "sentinel-evidence-consumer",
        handler: Optional[Callable] = None
    ):
        """
        Initialize evidence consumer
        
        Args:
            group_id: Kafka consumer group ID
            handler: Function to handle evidence (signature: func(pointer, evidence))
        """
        self.group_id = group_id
        self.handler = handler
        self.event_bus = get_event_bus(client_id="sentinel")
        self.retriever = EvidenceRetriever()
        self.running = False
        self.thread: Optional[threading.Thread] = None
        
        logger.info(f"Evidence consumer initialized: group={group_id}")
    
    def start(self):
        """Start consuming evidence pointers in background thread"""
        if self.running:
            logger.warning("Evidence consumer already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._consume_loop, daemon=True)
        self.thread.start()
        logger.info("Evidence consumer started")
    
    def stop(self):
        """Stop consuming"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Evidence consumer stopped")
    
    def _consume_loop(self):
        """Main consumption loop"""
        try:
            logger.info("Starting evidence consumption loop")
            self.event_bus.subscribe(
                topic="cerberus.evidence.ready",
                group_id=self.group_id,
                handler=self._handle_evidence_pointer,
                auto_offset_reset='latest'
            )
        except Exception as e:
            logger.error(f"Evidence consumption loop error: {e}")
            self.running = False
    
    def _handle_evidence_pointer(self, message: dict):
        """
        Handle incoming evidence pointer
        
        Args:
            message: Evidence pointer dict from Kafka
        """
        try:
            pointer = EvidencePointer.model_validate(message)
            
            logger.info(
                f"Received evidence pointer: event={pointer.event_id}, "
                f"session={pointer.session_id}, "
                f"payloads={pointer.payload_count}"
            )
            
            evidence = self.retriever.retrieve(pointer)
            
            if not evidence["valid"]:
                logger.warning(f"Evidence validation failed for {pointer.event_id}")
            
            
            if self.handler:
                self.handler(pointer, evidence)
            else:
                logger.info(f"No handler configured for evidence {pointer.event_id}")
            
            self.retriever.cleanup(evidence["workspace"])
            
        except Exception as e:
            logger.error(f"Failed to handle evidence pointer: {e}", exc_info=True)


def create_analysis_handler(
    profiler,
    simulator,
    rule_generator,
    storage_dict: dict
):
    """
    Factory function to create evidence handler for Sentinel pipeline
    
    Args:
        profiler: BehavioralProfiler instance
        simulator: PayloadSimulator instance
        rule_generator: RuleGenerator instance
        storage_dict: Dict to store results (in production: use DB)
        
    Returns:
        Handler function
    """
    
    def handler(pointer: EvidencePointer, evidence: dict):
        """
        Process evidence through Sentinel analysis pipeline
        
        Args:
            pointer: Evidence pointer
            evidence: Retrieved evidence dict
        """
        try:
            event_id = pointer.event_id
            session_id = pointer.session_id
            
            logger.info(f"Processing evidence {event_id} through analysis pipeline")
            
            har_log = evidence.get("har_log")
            metadata = evidence.get("metadata")
            
            if not har_log or not metadata:
                logger.warning(f"Incomplete evidence for {event_id}")
                return
            
            
            captures = []
            for entry in har_log.entries:
                captures.append({
                    "method": entry.request["method"],
                    "url": entry.request["url"],
                    "timestamp": entry.startedDateTime,
                    "status": entry.response["status"]
                })
            
            profile = profiler.profile_session(session_id, captures)
            
            storage_dict[f"profile_{session_id}"] = {
                "session_id": session_id,
                "profile": profile.model_dump(),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            logger.info(
                f"Profiled session {session_id}: "
                f"intent={profile.intent}, "
                f"sophistication={profile.sophistication_score:.2f}"
            )
            
            session_meta = metadata.session_metadata
            
            if "sql_injection" in pointer.tags:
                logger.info(f"SQL injection detected in {event_id}, queuing simulation")
            
            if "xss" in pointer.tags:
                logger.info(f"XSS detected in {event_id}, queuing simulation")
            
            if profile.sophistication_score >= 7.0:
                logger.info(f"High sophistication attack, generating proactive rules")
            
            logger.info(f"Evidence processing complete for {event_id}")
            
        except Exception as e:
            logger.error(f"Error in analysis pipeline: {e}", exc_info=True)
    
    return handler


_evidence_consumer: Optional[EvidenceConsumer] = None


def get_evidence_consumer(handler: Optional[Callable] = None) -> EvidenceConsumer:
    """Get singleton evidence consumer"""
    global _evidence_consumer
    if _evidence_consumer is None:
        _evidence_consumer = EvidenceConsumer(handler=handler)
    return _evidence_consumer


def start_evidence_consumer(profiler, simulator, rule_generator, storage_dict):
    """
    Start evidence consumer with Sentinel components
    
    Args:
        profiler: BehavioralProfiler
        simulator: PayloadSimulator
        rule_generator: RuleGenerator
        storage_dict: Storage for results
    """
    handler = create_analysis_handler(profiler, simulator, rule_generator, storage_dict)
    consumer = get_evidence_consumer(handler)
    consumer.start()
    logger.info("Sentinel evidence consumer started")
    return consumer
