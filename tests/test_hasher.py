import pytest
import tempfile
import os
import hashlib
import base64
from threat_radar.utils.hasher import Hasher


class TestHasher:
    """Test cases for the Hasher class"""

    def test_builtin_hash(self):
        """Test the builtin_hash method"""
        text = "test string"
        result = Hasher.builtin_hash(text)
        assert isinstance(result, int)
        assert result == hash(text)


    def test_crypto_hash_default_sha256(self):
        """Test crypto_hash with default SHA256 algorithm"""
        text = "test string"
        result = Hasher.crypto_hash(text)
        expected = hashlib.sha256(text.encode('utf-8')).hexdigest()
        assert result == expected

    def test_crypto_hash_md5(self):
        """Test crypto_hash with MD5 algorithm"""
        text = "test string"
        result = Hasher.crypto_hash(text, 'md5')
        expected = hashlib.md5(text.encode('utf-8')).hexdigest()
        assert result == expected

    def test_crypto_hash_sha1(self):
        """Test crypto_hash with SHA1 algorithm"""
        text = "test string"
        result = Hasher.crypto_hash(text, 'sha1')
        expected = hashlib.sha1(text.encode('utf-8')).hexdigest()
        assert result == expected

    def test_file_hash_sha256_hex(self):
        """Test file_hash with SHA256 and hex output"""
        content = "Hello, World!\n"

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            result = Hasher.file_hash(temp_path, 'sha256', 'hex')
            expected = hashlib.sha256(content.encode('utf-8')).hexdigest()
            assert result == expected
        finally:
            os.unlink(temp_path)

    def test_file_hash_md5_hex(self):
        """Test file_hash with MD5 and hex output"""
        content = "Hello, World!\n"

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            result = Hasher.file_hash(temp_path, 'md5', 'hex')
            expected = hashlib.md5(content.encode('utf-8')).hexdigest()
            assert result == expected
        finally:
            os.unlink(temp_path)

    def test_file_hash_sha256_text(self):
        """Test file_hash with SHA256 and text (base64) output"""
        content = "Hello, World!\n"

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            result = Hasher.file_hash(temp_path, 'sha256', 'text')
            hash_obj = hashlib.sha256(content.encode('utf-8'))
            expected = base64.b64encode(hash_obj.digest()).decode('utf-8')
            assert result == expected
        finally:
            os.unlink(temp_path)

    def test_file_hash_md5_text(self):
        """Test file_hash with MD5 and text (base64) output"""
        content = "Hello, World!\n"

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            result = Hasher.file_hash(temp_path, 'md5', 'text')
            hash_obj = hashlib.md5(content.encode('utf-8'))
            expected = base64.b64encode(hash_obj.digest()).decode('utf-8')
            assert result == expected
        finally:
            os.unlink(temp_path)

    def test_file_hash_large_file(self):
        """Test file_hash with a larger file to verify chunked reading"""
        content = "A" * 10000  # 10KB of data

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            result = Hasher.file_hash(temp_path, 'sha256', 'hex')
            expected = hashlib.sha256(content.encode('utf-8')).hexdigest()
            assert result == expected
        finally:
            os.unlink(temp_path)

    def test_file_hash_binary_file(self):
        """Test file_hash with binary content"""
        binary_content = b'\x00\x01\x02\x03\xff\xfe\xfd'

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(binary_content)
            temp_path = f.name

        try:
            result = Hasher.file_hash(temp_path, 'sha256', 'hex')
            expected = hashlib.sha256(binary_content).hexdigest()
            assert result == expected
        finally:
            os.unlink(temp_path)

    def test_file_hash_empty_file(self):
        """Test file_hash with empty file"""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            result = Hasher.file_hash(temp_path, 'sha256', 'hex')
            expected = hashlib.sha256(b'').hexdigest()
            assert result == expected
        finally:
            os.unlink(temp_path)

    def test_file_hash_invalid_algorithm(self):
        """Test file_hash with invalid algorithm"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test")
            temp_path = f.name

        try:
            with pytest.raises(ValueError, match="Algorithm must be 'sha256' or 'md5'"):
                Hasher.file_hash(temp_path, 'invalid', 'hex')
        finally:
            os.unlink(temp_path)

    def test_file_hash_invalid_output_format(self):
        """Test file_hash with invalid output format"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test")
            temp_path = f.name

        try:
            with pytest.raises(ValueError, match="Output format must be 'hex' or 'text'"):
                Hasher.file_hash(temp_path, 'sha256', 'invalid')
        finally:
            os.unlink(temp_path)

    def test_file_hash_nonexistent_file(self):
        """Test file_hash with non-existent file"""
        nonexistent_path = "/tmp/nonexistent_file_12345.txt"
        with pytest.raises(FileNotFoundError, match=f"File not found: {nonexistent_path}"):
            Hasher.file_hash(nonexistent_path, 'sha256', 'hex')

    def test_file_hash_case_insensitive_algorithm(self):
        """Test file_hash with case-insensitive algorithm names"""
        content = "test content"

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            result_upper = Hasher.file_hash(temp_path, 'SHA256', 'hex')
            result_lower = Hasher.file_hash(temp_path, 'sha256', 'hex')
            result_mixed = Hasher.file_hash(temp_path, 'ShA256', 'hex')

            assert result_upper == result_lower == result_mixed
        finally:
            os.unlink(temp_path)

    def test_file_hash_case_insensitive_format(self):
        """Test file_hash with case-insensitive output format names"""
        content = "test content"

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(content)
            temp_path = f.name

        try:
            result_upper = Hasher.file_hash(temp_path, 'sha256', 'HEX')
            result_lower = Hasher.file_hash(temp_path, 'sha256', 'hex')
            result_mixed = Hasher.file_hash(temp_path, 'sha256', 'HeX')

            assert result_upper == result_lower == result_mixed
        finally:
            os.unlink(temp_path)

