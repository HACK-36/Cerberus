"""
Stage 1: Evidence Consumer - Kafka consumer for evidence_created events
Fetches evidence from MinIO, verifies integrity, and triggers analysis
"""
import json
import hashlib
import os
from typing import Dict, Optional
from datetime import datetime
import asyncio

try:
    from kafka import KafkaConsumer
    from kafka.errors import KafkaError
except ImportError:
    print("[WARNING] kafka-python not installed. Install with: pip install kafka-python")
    KafkaConsumer = None
    KafkaError = Exception

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.storage.minio_client import MinIOClient
from shared.utils.logging import get_logger
from shared.utils.metrics import EVIDENCE_OPERATIONS, KAFKA_MESSAGES

logger = get_logger(__name__)


class EvidenceConsumer:
    """
    Consumes evidence_created events from Kafka
    Fetches evidence packages from MinIO
    Verifies integrity and triggers feature extraction
    """
    
    def __init__(
        self,
        kafka_bootstrap_servers: str = "kafka:29092",
        topic: str = "events.evidence_created",
        group_id: str = "sentinel-evidence-processor",
        minio_client: Optional[MinIOClient] = None
    ):
        self.kafka_bootstrap_servers = kafka_bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self.minio_client = minio_client or MinIOClient()
        self.consumer = None
        self.running = False
        
        logger.info(f"Evidence consumer initialized for topic: {topic}")
    
    def start(self):
        """Start consuming evidence events"""
        if not KafkaConsumer:
            logger.error("Kafka consumer not available. Install kafka-python.")
            return
        
        try:
            self.consumer = KafkaConsumer(
                self.topic,
                bootstrap_servers=self.kafka_bootstrap_servers,
                group_id=self.group_id,
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                auto_offset_reset='earliest',
                enable_auto_commit=True,
                max_poll_records=10
            )
            
            self.running = True
            logger.info(f"Started consuming from {self.topic}")
            
            # Emit metric
            KAFKA_MESSAGES.labels(topic=self.topic, status="started").inc()
            
            for message in self.consumer:
                if not self.running:
                    break
                
                try:
                    event = message.value
                    self._process_evidence_event(event)
                    
                except Exception as e:
                    logger.error(f"Error processing message: {e}", exc_info=True)
                    KAFKA_MESSAGES.labels(topic=self.topic, status="error").inc()
        
        except KafkaError as e:
            logger.error(f"Kafka consumer error: {e}")
            KAFKA_MESSAGES.labels(topic=self.topic, status="failed").inc()
        
        finally:
            self.stop()
    
    def stop(self):
        """Stop consuming"""
        self.running = False
        if self.consumer:
            self.consumer.close()
            logger.info("Evidence consumer stopped")
    
    def _process_evidence_event(self, event: Dict):
        """
        Process a single evidence_created event
        
        Event schema:
        {
          "event_id": "uuid-123",
          "timestamp": "2025-11-08T22:00:00Z",
          "source": "labyrinth",
          "session_id": "lab-123",
          "evidence_uri": "minio://cerberus/evidence/lab-123.tar.gz",
          "tags": ["poi", "sql_injection-suspected"],
          "meta": {...}
        }
        """
        event_id = event.get("event_id", "unknown")
        session_id = event.get("session_id", "unknown")
        evidence_uri = event.get("evidence_uri", "")
        
        logger.info(f"[{event_id}] Processing evidence for session: {session_id}")
        
        try:
            # Parse MinIO URI
            evidence_package = self._fetch_evidence(evidence_uri)
            
            if not evidence_package:
                logger.warning(f"[{event_id}] Failed to fetch evidence from {evidence_uri}")
                return
            
            # Verify integrity
            if not self._verify_integrity(evidence_package):
                logger.error(f"[{event_id}] Evidence integrity check FAILED for {session_id}")
                EVIDENCE_OPERATIONS.labels(operation="verify", status="failed").inc()
                return
            
            logger.info(f"[{event_id}] Evidence verified successfully for {session_id}")
            EVIDENCE_OPERATIONS.labels(operation="verify", status="success").inc()
            
            # Enrich with metadata
            enriched_evidence = self._enrich_evidence(evidence_package, event)
            
            # Store for feature extraction (next stage)
            self._store_for_extraction(session_id, enriched_evidence)
            
            # Emit event for next stage
            self._emit_evidence_ready(session_id, event_id)
            
            logger.info(f"[{event_id}] Evidence processing complete for {session_id}")
        
        except Exception as e:
            logger.error(f"[{event_id}] Error processing evidence: {e}", exc_info=True)
    
    def _fetch_evidence(self, evidence_uri: str) -> Optional[Dict]:
        """
        Fetch evidence package from MinIO
        
        URI format: minio://cerberus/evidence/session-id.tar.gz
        """
        try:
            # Parse URI
            if not evidence_uri.startswith("minio://"):
                logger.error(f"Invalid evidence URI format: {evidence_uri}")
                return None
            
            # Extract bucket and object path
            # Format: minio://bucket/path/to/object
            parts = evidence_uri.replace("minio://", "").split("/", 1)
            if len(parts) != 2:
                logger.error(f"Invalid URI structure: {evidence_uri}")
                return None
            
            bucket_name = parts[0]
            object_path = parts[1]
            
            logger.info(f"Fetching evidence: bucket={bucket_name}, object={object_path}")
            
            # Download from MinIO
            evidence_data = self.minio_client.get_object(bucket_name, object_path)
            
            if not evidence_data:
                return None
            
            # Parse evidence package (assuming JSON format for now)
            # In production: handle tar.gz archives
            evidence_package = json.loads(evidence_data) if isinstance(evidence_data, (str, bytes)) else evidence_data
            
            EVIDENCE_OPERATIONS.labels(operation="fetch", status="success").inc()
            return evidence_package
        
        except Exception as e:
            logger.error(f"Error fetching evidence: {e}", exc_info=True)
            EVIDENCE_OPERATIONS.labels(operation="fetch", status="failed").inc()
            return None
    
    def _verify_integrity(self, evidence_package: Dict) -> bool:
        """
        Verify evidence integrity using checksums and signatures
        
        Checks:
        1. Presence of signed_manifest.json
        2. SHA256 checksums match
        3. Signature verification (simplified for now)
        """
        try:
            manifest = evidence_package.get("signed_manifest", {})
            
            if not manifest:
                logger.warning("No signed manifest found in evidence package")
                return False
            
            # Verify checksums for each component
            checksums = manifest.get("checksums", {})
            
            for component, expected_hash in checksums.items():
                component_data = evidence_package.get(component)
                
                if component_data is None:
                    logger.error(f"Missing component: {component}")
                    return False
                
                # Calculate actual hash
                actual_hash = self._calculate_sha256(component_data)
                
                if actual_hash != expected_hash:
                    logger.error(f"Checksum mismatch for {component}: expected={expected_hash}, actual={actual_hash}")
                    return False
            
            # TODO: Verify cryptographic signature
            # signature = manifest.get("signature")
            # if not self._verify_signature(manifest, signature):
            #     return False
            
            return True
        
        except Exception as e:
            logger.error(f"Error verifying integrity: {e}", exc_info=True)
            return False
    
    def _calculate_sha256(self, data) -> str:
        """Calculate SHA256 hash of data"""
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return hashlib.sha256(data).hexdigest()
    
    def _enrich_evidence(self, evidence_package: Dict, event: Dict) -> Dict:
        """
        Enrich evidence with additional metadata
        
        Adds:
        - Event metadata
        - Timestamps
        - Source information
        """
        enriched = evidence_package.copy()
        
        enriched["enrichment"] = {
            "event_id": event.get("event_id"),
            "source": event.get("source"),
            "received_at": datetime.utcnow().isoformat(),
            "tags": event.get("tags", []),
            "meta": event.get("meta", {})
        }
        
        return enriched
    
    def _store_for_extraction(self, session_id: str, evidence: Dict):
        """
        Store evidence locally for feature extraction
        
        In production: use persistent storage or message queue
        """
        try:
            # Create working directory
            work_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'evidence_working')
            os.makedirs(work_dir, exist_ok=True)
            
            # Save evidence
            evidence_file = os.path.join(work_dir, f"{session_id}.json")
            with open(evidence_file, 'w') as f:
                json.dump(evidence, f, indent=2)
            
            logger.info(f"Evidence stored for extraction: {evidence_file}")
        
        except Exception as e:
            logger.error(f"Error storing evidence: {e}", exc_info=True)
    
    def _emit_evidence_ready(self, session_id: str, event_id: str):
        """
        Emit event indicating evidence is ready for feature extraction
        
        In production: publish to Kafka topic "events.evidence_ready"
        """
        try:
            event = {
                "event_id": f"ready_{event_id}",
                "timestamp": datetime.utcnow().isoformat(),
                "source": "sentinel-consumer",
                "session_id": session_id,
                "status": "ready_for_extraction"
            }
            
            # Store event locally (in production: publish to Kafka)
            events_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'events')
            os.makedirs(events_dir, exist_ok=True)
            
            event_file = os.path.join(events_dir, f"evidence_ready_{session_id}.json")
            with open(event_file, 'w') as f:
                json.dump(event, f, indent=2)
            
            logger.info(f"Evidence ready event emitted for {session_id}")
        
        except Exception as e:
            logger.error(f"Error emitting event: {e}", exc_info=True)


# Entry point for running as standalone service
if __name__ == "__main__":
    consumer = EvidenceConsumer()
    
    try:
        logger.info("Starting Sentinel evidence consumer...")
        consumer.start()
    except KeyboardInterrupt:
        logger.info("Shutting down evidence consumer...")
        consumer.stop()
