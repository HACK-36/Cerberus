"""
Unit tests for Evidence Builder
"""
import pytest
import os
import tempfile
import shutil
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from shared.evidence.builder import EvidenceBuilder
from shared.evidence.models import PayloadArtifact, BehaviorProfile, TTPs


class TestEvidenceBuilder:
    """Test suite for EvidenceBuilder"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.event_id = "evt_test_001"
        self.session_id = "sess_test_001"
        self.attacker_ip = "203.0.113.42"
        self.user_agent = "sqlmap/1.5.2"
        
        self.builder = EvidenceBuilder(
            event_id=self.event_id,
            session_id=self.session_id,
            attacker_ip=self.attacker_ip,
            user_agent=self.user_agent
        )
    
    def teardown_method(self):
        """Cleanup after tests"""
        if hasattr(self.builder, 'workspace') and os.path.exists(self.builder.workspace):
            shutil.rmtree(self.builder.workspace, ignore_errors=True)
    
    def test_initialization(self):
        """Test builder initialization"""
        assert self.builder.event_id == self.event_id
        assert self.builder.session_id == self.session_id
        assert self.builder.attacker_ip == self.attacker_ip
        assert self.builder.user_agent == self.user_agent
        assert os.path.exists(self.builder.workspace)
        assert len(self.builder.har_entries) == 0
        assert len(self.builder.payloads) == 0
    
    def test_fingerprint_generation(self):
        """Test session fingerprint generation"""
        fingerprint = self.builder.fingerprint
        assert fingerprint is not None
        assert len(fingerprint) == 16
        assert isinstance(fingerprint, str)
    
    def test_add_har_entry(self):
        """Test adding HAR entry"""
        self.builder.add_har_entry(
            method="GET",
            url="/api/users?id=1",
            request_headers={"User-Agent": "test", "Host": "example.com"},
            request_body="",
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"users": []}',
            start_time=datetime.utcnow(),
            duration_ms=123.45
        )
        
        assert len(self.builder.har_entries) == 1
        entry = self.builder.har_entries[0]
        assert entry.request["method"] == "GET"
        assert entry.response["status"] == 200
        assert entry.time == 123.45
    
    def test_add_payload(self):
        """Test adding payload"""
        self.builder.add_payload(
            payload_type="sql_injection",
            payload_value="1' OR '1'='1",
            location="query.id",
            confidence=0.95
        )
        
        assert len(self.builder.payloads) == 1
        payload = self.builder.payloads[0]
        assert payload.payload_type == "sql_injection"
        assert payload.payload_value == "1' OR '1'='1"
        assert payload.confidence == 0.95
        assert payload.checksum is not None
    
    def test_add_payload_with_file(self):
        """Test adding payload saved as file"""
        large_payload = "x" * 200  # Large payload
        
        self.builder.add_payload(
            payload_type="command_injection",
            payload_value=large_payload,
            location="body.cmd",
            confidence=0.85,
            save_as_file=True
        )
        
        payload = self.builder.payloads[0]
        assert payload.file_path is not None
        
        # Verify file was created
        full_path = os.path.join(self.builder.workspace, payload.file_path)
        assert os.path.exists(full_path)
        
        # Verify content
        with open(full_path, 'r') as f:
            content = f.read()
            assert content == large_payload
    
    def test_add_tag(self):
        """Test adding tags"""
        self.builder.add_tag("sql_injection")
        self.builder.add_tag("high_severity")
        self.builder.add_tag("sql_injection")  # Duplicate
        
        assert len(self.builder.tags) == 2
        assert "sql_injection" in self.builder.tags
        assert "high_severity" in self.builder.tags
    
    def test_add_uploaded_file(self):
        """Test tracking uploaded malicious file"""
        # Create test file
        test_file = os.path.join(self.builder.workspace, "malicious.txt")
        with open(test_file, 'w') as f:
            f.write("malicious content")
        
        self.builder.add_uploaded_file(
            filename="malicious.txt",
            file_path=test_file,
            file_size=len("malicious content")
        )
        
        assert len(self.builder.uploaded_files) == 1
        file_info = self.builder.uploaded_files[0]
        assert file_info["filename"] == "malicious.txt"
        assert file_info["checksum"] is not None
    
    @patch('shared.evidence.builder.get_storage_client')
    def test_build_and_upload(self, mock_storage_client):
        """Test building and uploading evidence package"""
        # Setup mock storage client
        mock_storage = MagicMock()
        mock_storage.ensure_bucket.return_value = True
        mock_storage.upload_file.return_value = {
            "bucket": "labyrinth-evidence",
            "object": "evt_test_001/session.har",
            "etag": "abc123",
            "size": 1024,
            "checksum": "def456",
            "uploaded_at": datetime.utcnow().isoformat()
        }
        mock_storage_client.return_value = mock_storage
        
        # Add some data
        self.builder.add_har_entry(
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
        
        self.builder.add_payload(
            payload_type="sql_injection",
            payload_value="test payload",
            location="query",
            confidence=0.9
        )
        
        # Build and upload
        pointer = self.builder.build_and_upload()
        
        # Verify pointer
        assert pointer.event_id == self.event_id
        assert pointer.session_id == self.session_id
        assert pointer.attacker_ip == self.attacker_ip
        assert pointer.payload_count == 1
        assert pointer.request_count == 1
        assert pointer.checksum is not None
        
        # Verify storage calls
        mock_storage.ensure_bucket.assert_called_once()
        assert mock_storage.upload_file.call_count >= 1
    
    @patch('shared.evidence.builder.get_storage_client')
    def test_build_with_behavior_profile(self, mock_storage_client):
        """Test building with behavioral profile"""
        mock_storage = MagicMock()
        mock_storage.ensure_bucket.return_value = True
        mock_storage.upload_file.return_value = {
            "bucket": "test",
            "object": "test",
            "etag": "test",
            "size": 100,
            "checksum": "test",
            "uploaded_at": datetime.utcnow().isoformat()
        }
        mock_storage_client.return_value = mock_storage
        
        # Create behavior profile
        profile = BehaviorProfile(
            intent="exploitation",
            sophistication_score=8.5,
            ttps=TTPs(
                techniques=["T1190", "T1059"],
                tactics=["Initial Access", "Execution"]
            ),
            action_sequence=["probe", "exploit"],
            automation_detected=True,
            tool_signatures=["sqlmap"]
        )
        
        # Add minimal data
        self.builder.add_har_entry(
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
        
        # Build with profile
        pointer = self.builder.build_and_upload(behavior_profile=profile)
        
        assert pointer is not None
        
        # Verify behavior.json was created (check upload calls)
        upload_calls = [call[0] for call in mock_storage.upload_file.call_args_list]
        object_names = [call[1] for call in upload_calls]
        
        # Should have uploaded metadata.json, session.har, and behavior.json
        assert any("behavior.json" in name for name in object_names)
    
    def test_workspace_cleanup_after_upload(self):
        """Test that workspace is cleaned up after successful upload"""
        # Store workspace path
        workspace_path = self.builder.workspace
        assert os.path.exists(workspace_path)
        
        with patch('shared.evidence.builder.get_storage_client') as mock_storage_client:
            mock_storage = MagicMock()
            mock_storage.ensure_bucket.return_value = True
            mock_storage.upload_file.return_value = {
                "bucket": "test",
                "object": "test",
                "etag": "test",
                "size": 100,
                "checksum": "abc",
                "uploaded_at": datetime.utcnow().isoformat()
            }
            mock_storage_client.return_value = mock_storage
            
            # Add minimal data and upload
            self.builder.add_har_entry(
                method="GET",
                url="/",
                request_headers={},
                request_body="",
                response_status=200,
                response_headers={},
                response_body="",
                start_time=datetime.utcnow(),
                duration_ms=10
            )
            
            pointer = self.builder.build_and_upload()
            
            # Workspace should be cleaned up
            assert not os.path.exists(workspace_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
