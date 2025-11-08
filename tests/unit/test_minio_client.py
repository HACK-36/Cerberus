"""
Unit tests for MinIO Storage Client
"""
import pytest
import os
import tempfile
from unittest.mock import Mock, patch, MagicMock
from datetime import timedelta

from shared.storage.minio_client import CerberusStorageClient


class TestMinIOClient:
    """Test suite for MinIO storage client"""
    
    @patch('shared.storage.minio_client.Minio')
    def setup_method(self, mock_minio):
        """Setup test fixtures"""
        self.mock_minio = mock_minio
        self.client = CerberusStorageClient(
            endpoint="localhost:9000",
            access_key="test_key",
            secret_key="test_secret",
            secure=False
        )
    
    def test_initialization(self):
        """Test client initialization"""
        assert self.client.endpoint == "localhost:9000"
        assert self.client.access_key == "test_key"
        assert self.client.secret_key == "test_secret"
        assert self.client.secure == False
    
    @patch('shared.storage.minio_client.Minio')
    def test_ensure_bucket_creates_if_not_exists(self, mock_minio_class):
        """Test bucket creation when it doesn't exist"""
        mock_client = MagicMock()
        mock_client.bucket_exists.return_value = False
        mock_minio_class.return_value = mock_client
        
        client = CerberusStorageClient()
        result = client.ensure_bucket("test-bucket")
        
        assert result == True
        mock_client.bucket_exists.assert_called_once_with("test-bucket")
        mock_client.make_bucket.assert_called_once_with("test-bucket")
    
    @patch('shared.storage.minio_client.Minio')
    def test_ensure_bucket_skips_if_exists(self, mock_minio_class):
        """Test bucket creation skipped when bucket exists"""
        mock_client = MagicMock()
        mock_client.bucket_exists.return_value = True
        mock_minio_class.return_value = mock_client
        
        client = CerberusStorageClient()
        result = client.ensure_bucket("test-bucket")
        
        assert result == True
        mock_client.bucket_exists.assert_called_once()
        mock_client.make_bucket.assert_not_called()
    
    @patch('shared.storage.minio_client.Minio')
    def test_upload_file(self, mock_minio_class):
        """Test file upload"""
        # Create test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test content")
            test_file = f.name
        
        try:
            mock_client = MagicMock()
            mock_result = MagicMock()
            mock_result.etag = "abc123"
            mock_client.fput_object.return_value = mock_result
            mock_minio_class.return_value = mock_client
            
            client = CerberusStorageClient()
            result = client.upload_file(
                "test-bucket",
                "test/file.txt",
                test_file
            )
            
            assert result["bucket"] == "test-bucket"
            assert result["object"] == "test/file.txt"
            assert result["etag"] == "abc123"
            assert "checksum" in result
            assert "size" in result
            
            mock_client.fput_object.assert_called_once()
        
        finally:
            os.unlink(test_file)
    
    @patch('shared.storage.minio_client.Minio')
    def test_upload_bytes(self, mock_minio_class):
        """Test bytes upload"""
        mock_client = MagicMock()
        mock_result = MagicMock()
        mock_result.etag = "def456"
        mock_client.put_object.return_value = mock_result
        mock_minio_class.return_value = mock_client
        
        client = CerberusStorageClient()
        test_data = b"test bytes content"
        
        result = client.upload_bytes(
            "test-bucket",
            "test/bytes.bin",
            test_data,
            content_type="application/octet-stream"
        )
        
        assert result["bucket"] == "test-bucket"
        assert result["object"] == "test/bytes.bin"
        assert result["size"] == len(test_data)
        assert "checksum" in result
    
    @patch('shared.storage.minio_client.Minio')
    def test_download_file(self, mock_minio_class):
        """Test file download"""
        mock_client = MagicMock()
        mock_minio_class.return_value = mock_client
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            dest_file = f.name
        
        try:
            # Create source file for testing
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write("downloaded content")
                source_file = f.name
            
            # Mock will "download" by creating file
            def mock_fget(bucket, obj, path):
                with open(path, 'w') as f:
                    f.write("downloaded content")
            
            mock_client.fget_object.side_effect = mock_fget
            
            client = CerberusStorageClient()
            result = client.download_file(
                "test-bucket",
                "test/file.txt",
                dest_file
            )
            
            assert result["bucket"] == "test-bucket"
            assert result["object"] == "test/file.txt"
            assert result["local_path"] == dest_file
            assert os.path.exists(dest_file)
        
        finally:
            if os.path.exists(dest_file):
                os.unlink(dest_file)
            if os.path.exists(source_file):
                os.unlink(source_file)
    
    @patch('shared.storage.minio_client.Minio')
    def test_download_bytes(self, mock_minio_class):
        """Test bytes download"""
        mock_client = MagicMock()
        mock_response = MagicMock()
        test_data = b"test data"
        mock_response.read.return_value = test_data
        mock_client.get_object.return_value = mock_response
        mock_minio_class.return_value = mock_client
        
        client = CerberusStorageClient()
        result = client.download_bytes("test-bucket", "test/file.bin")
        
        assert result == test_data
        mock_response.close.assert_called_once()
        mock_response.release_conn.assert_called_once()
    
    @patch('shared.storage.minio_client.Minio')
    def test_list_objects(self, mock_minio_class):
        """Test listing objects"""
        mock_client = MagicMock()
        
        # Create mock objects
        mock_obj1 = MagicMock()
        mock_obj1.object_name = "test/file1.txt"
        mock_obj1.size = 100
        mock_obj1.last_modified = None
        mock_obj1.etag = "abc"
        
        mock_obj2 = MagicMock()
        mock_obj2.object_name = "test/file2.txt"
        mock_obj2.size = 200
        mock_obj2.last_modified = None
        mock_obj2.etag = "def"
        
        mock_client.list_objects.return_value = [mock_obj1, mock_obj2]
        mock_minio_class.return_value = mock_client
        
        client = CerberusStorageClient()
        result = client.list_objects("test-bucket", prefix="test/")
        
        assert len(result) == 2
        assert result[0]["name"] == "test/file1.txt"
        assert result[0]["size"] == 100
        assert result[1]["name"] == "test/file2.txt"
    
    @patch('shared.storage.minio_client.Minio')
    def test_delete_object(self, mock_minio_class):
        """Test object deletion"""
        mock_client = MagicMock()
        mock_minio_class.return_value = mock_client
        
        client = CerberusStorageClient()
        result = client.delete_object("test-bucket", "test/file.txt")
        
        assert result == True
        mock_client.remove_object.assert_called_once_with("test-bucket", "test/file.txt")
    
    @patch('shared.storage.minio_client.Minio')
    def test_get_presigned_url(self, mock_minio_class):
        """Test presigned URL generation"""
        mock_client = MagicMock()
        mock_client.presigned_get_object.return_value = "https://minio/presigned-url"
        mock_minio_class.return_value = mock_client
        
        client = CerberusStorageClient()
        url = client.get_presigned_url(
            "test-bucket",
            "test/file.txt",
            expires=timedelta(hours=1)
        )
        
        assert url == "https://minio/presigned-url"
        mock_client.presigned_get_object.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
