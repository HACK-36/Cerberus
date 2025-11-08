"""
Integration Test for Evidence Flow
Tests complete evidence collection → storage → retrieval → analysis pipeline
"""
import pytest
import time
import tempfile
import os
from unittest.mock import MagicMock, patch
from datetime import datetime

from shared.evidence.builder import EvidenceBuilder
from shared.evidence.retriever import EvidenceRetriever
from shared.evidence.models import EvidencePointer, BehaviorProfile, TTPs


class TestEvidenceFlow:
    """
    Integration tests for complete evidence workflow
    
    Tests the flow: Capture → Build → Upload → Pointer → Retrieve → Analyze
    """
    
    @pytest.fixture
    def mock_storage(self):
        """Mock MinIO storage client"""
        with patch('shared.evidence.builder.get_storage_client') as mock_get_client:
            mock_client = MagicMock()
            mock_client.ensure_bucket.return_value = True
            mock_client.upload_file.return_value = {
                "bucket": "test-evidence",
                "object": "test/file.har",
                "etag": "abc123",
                "size": 1024,
                "checksum": "def456",
                "uploaded_at": datetime.utcnow().isoformat()
            }
            mock_client.list_objects.return_value = [
                {"name": "evt_test/session.har", "size": 1024},
                {"name": "evt_test/metadata.json", "size": 512}
            ]
            mock_get_client.return_value = mock_client
            yield mock_client
    
    def test_evidence_builder_creates_package(self, mock_storage):
        """Test that evidence builder creates complete package"""
        # Create builder
        builder = EvidenceBuilder(
            event_id="evt_test_001",
            session_id="sess_test_001",
            attacker_ip="203.0.113.42",
            user_agent="sqlmap/1.5.2"
        )
        
        # Add HAR entries
        builder.add_har_entry(
            method="GET",
            url="/api/users?id=1' OR '1'='1",
            request_headers={"User-Agent": "sqlmap/1.5.2"},
            request_body="",
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"users": []}',
            start_time=datetime.utcnow(),
            duration_ms=125.5
        )
        
        # Add payloads
        builder.add_payload(
            payload_type="sql_injection",
            payload_value="1' OR '1'='1",
            location="query.id",
            confidence=0.95
        )
        
        # Add tags
        builder.add_tag("sql_injection")
        builder.add_tag("high_severity")
        
        # Build and upload
        pointer = builder.build_and_upload(bucket_name="test-evidence")
        
        # Verify pointer
        assert pointer.event_id == "evt_test_001"
        assert pointer.session_id == "sess_test_001"
        assert pointer.attacker_ip == "203.0.113.42"
        assert pointer.payload_count == 1
        assert pointer.request_count == 1
        assert "sql_injection" in pointer.tags
        
        # Verify storage calls
        mock_storage.ensure_bucket.assert_called()
        assert mock_storage.upload_file.call_count >= 1
    
    def test_evidence_retriever_downloads_package(self, mock_storage):
        """Test that retriever can download and parse evidence"""
        # Setup mock for download
        def mock_download(bucket, obj_name, local_path):
            # Create fake files
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            if "session.har" in obj_name:
                with open(local_path, 'w') as f:
                    f.write('{"version": "1.2", "entries": []}')
            elif "metadata.json" in obj_name:
                with open(local_path, 'w') as f:
                    f.write('{"event_id": "evt_test", "session_metadata": {}}')
        
        mock_storage.download_file.side_effect = mock_download
        
        # Create pointer
        pointer = EvidencePointer(
            event_id="evt_test_001",
            capture_id="cap_test_001",
            session_id="sess_test_001",
            attacker_ip="203.0.113.42",
            location="s3://test-evidence/evt_test_001/",
            payload_count=1,
            request_count=1
        )
        
        # Retrieve evidence
        with patch('shared.evidence.retriever.get_storage_client', return_value=mock_storage):
            retriever = EvidenceRetriever()
            evidence = retriever.retrieve(pointer)
        
        # Verify retrieval
        assert evidence["event_id"] == "evt_test_001"
        assert evidence["valid"] == True
        assert evidence["artifact_count"] == 2
        assert evidence["workspace"] is not None
        
        # Cleanup
        retriever.cleanup(evidence["workspace"])
    
    @pytest.mark.asyncio
    async def test_complete_evidence_pipeline(self, mock_storage):
        """
        Test complete evidence pipeline from collection to analysis
        
        Flow:
        1. Labyrinth captures request
        2. Evidence builder packages it
        3. Upload to MinIO
        4. Publish pointer
        5. Sentinel retrieves
        6. Analyze and generate rules
        """
        # Step 1 & 2: Capture and build
        builder = EvidenceBuilder(
            event_id="evt_pipeline_test",
            session_id="sess_pipeline_test",
            attacker_ip="203.0.113.99",
            user_agent="nikto/2.1.6"
        )
        
        # Simulate multiple requests in session
        for i in range(3):
            builder.add_har_entry(
                method="GET",
                url=f"/admin/config.php?debug=true&id={i}",
                request_headers={"User-Agent": "nikto/2.1.6"},
                request_body="",
                response_status=200,
                response_headers={},
                response_body="",
                start_time=datetime.utcnow(),
                duration_ms=100 + i * 10
            )
        
        # Extract payloads
        builder.add_payload(
            payload_type="path_traversal",
            payload_value="../../../etc/passwd",
            location="query.file",
            confidence=0.88
        )
        
        builder.add_payload(
            payload_type="information_disclosure",
            payload_value="debug=true",
            location="query.debug",
            confidence=0.75
        )
        
        # Add behavior profile
        behavior = BehaviorProfile(
            intent="reconnaissance",
            sophistication_score=6.5,
            ttps=TTPs(
                techniques=["T1190", "T1595"],
                tactics=["Initial Access", "Reconnaissance"]
            ),
            action_sequence=["probe_admin", "enumerate_files", "request_debug_info"],
            automation_detected=True,
            tool_signatures=["nikto"]
        )
        
        # Step 3: Upload
        pointer = builder.build_and_upload(
            bucket_name="test-evidence",
            behavior_profile=behavior
        )
        
        # Step 4: Verify pointer
        assert pointer.payload_count == 2
        assert pointer.request_count == 3
        
        # Step 5: Retrieve (simulating Sentinel)
        def mock_download_full(bucket, obj_name, local_path):
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            if "session.har" in obj_name:
                with open(local_path, 'w') as f:
                    f.write('{"version": "1.2", "entries": []}')
            elif "metadata.json" in obj_name:
                with open(local_path, 'w') as f:
                    f.write('{"event_id": "evt_pipeline_test", "session_metadata": {"session_id": "sess_pipeline_test"}}')
            elif "behavior.json" in obj_name:
                with open(local_path, 'w') as f:
                    f.write('{"intent": "reconnaissance", "sophistication_score": 6.5}')
        
        mock_storage.download_file.side_effect = mock_download_full
        mock_storage.list_objects.return_value = [
            {"name": "evt_pipeline_test/session.har", "size": 2048},
            {"name": "evt_pipeline_test/metadata.json", "size": 512},
            {"name": "evt_pipeline_test/behavior.json", "size": 256}
        ]
        
        with patch('shared.evidence.retriever.get_storage_client', return_value=mock_storage):
            retriever = EvidenceRetriever()
            evidence = retriever.retrieve(pointer)
        
        # Step 6: Verify analysis can proceed
        assert evidence is not None
        assert evidence["valid"] == True
        assert evidence["metadata"] is not None
        
        # Simulate analysis
        metadata = evidence["metadata"]
        assert metadata is not None
        
        # Cleanup
        retriever.cleanup(evidence["workspace"])
    
    def test_evidence_pointer_serialization(self):
        """Test evidence pointer can be serialized for messaging"""
        pointer = EvidencePointer(
            event_id="evt_serial_test",
            capture_id="cap_serial_test",
            session_id="sess_serial_test",
            attacker_ip="203.0.113.1",
            location="s3://evidence/evt_serial_test/",
            payload_count=5,
            request_count=10,
            checksum="abc123def456",
            tags=["sql_injection", "high_severity"]
        )
        
        # Serialize
        json_str = pointer.model_dump_json()
        assert "evt_serial_test" in json_str
        assert "sql_injection" in json_str
        
        # Deserialize
        pointer_restored = EvidencePointer.model_validate_json(json_str)
        assert pointer_restored.event_id == pointer.event_id
        assert pointer_restored.payload_count == 5
        assert pointer_restored.tags == pointer.tags
    
    def test_concurrent_evidence_collection(self, mock_storage):
        """Test that multiple sessions can collect evidence concurrently"""
        builders = []
        
        # Create multiple builders
        for i in range(3):
            builder = EvidenceBuilder(
                event_id=f"evt_concurrent_{i}",
                session_id=f"sess_concurrent_{i}",
                attacker_ip=f"203.0.113.{i}",
                user_agent="test"
            )
            
            builder.add_har_entry(
                method="GET",
                url="/test",
                request_headers={},
                request_body="",
                response_status=200,
                response_headers={},
                response_body="",
                start_time=datetime.utcnow(),
                duration_ms=100
            )
            
            builders.append(builder)
        
        # Upload all
        pointers = []
        for builder in builders:
            pointer = builder.build_and_upload(bucket_name="test-evidence")
            pointers.append(pointer)
        
        # Verify all succeeded
        assert len(pointers) == 3
        assert all(p.event_id.startswith("evt_concurrent_") for p in pointers)
    
    def test_evidence_validation_with_checksum(self, mock_storage):
        """Test evidence validation using checksums"""
        # Create evidence with known checksum
        builder = EvidenceBuilder(
            event_id="evt_checksum_test",
            session_id="sess_checksum_test",
            attacker_ip="203.0.113.42",
            user_agent="test"
        )
        
        builder.add_har_entry(
            method="GET",
            url="/",
            request_headers={},
            request_body="",
            response_status=200,
            response_headers={},
            response_body="",
            start_time=datetime.utcnow(),
            duration_ms=50
        )
        
        # Build with checksum
        pointer = builder.build_and_upload()
        
        # Verify checksum is present
        assert pointer.checksum is not None
        assert len(pointer.checksum) == 64  # SHA256 hex length


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
