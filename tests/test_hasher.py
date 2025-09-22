import pytest
from threat_radar.utils.hasher import Hasher, HashTable


class TestHasher:
    """Test cases for the Hasher class"""

    def test_simple_hash_basic(self):
        """Test basic functionality of simple_hash"""
        result = Hasher.simple_hash("test")
        assert isinstance(result, int)
        assert 0 <= result < 1000  # Default table_size

    def test_simple_hash_custom_table_size(self):
        """Test simple_hash with custom table size"""
        result = Hasher.simple_hash("test", 100)
        assert 0 <= result < 100

    def test_simple_hash_consistency(self):
        """Test that same input produces same output"""
        text = "Hello, World!"
        result1 = Hasher.simple_hash(text)
        result2 = Hasher.simple_hash(text)
        assert result1 == result2

    def test_simple_hash_different_inputs(self):
        """Test that different inputs produce different outputs"""
        result1 = Hasher.simple_hash("hello")
        result2 = Hasher.simple_hash("world")
        assert result1 != result2

    def test_djb2_hash_basic(self):
        """Test basic functionality of djb2_hash"""
        result = Hasher.djb2_hash("test")
        assert isinstance(result, int)
        assert result >= 0

    def test_djb2_hash_consistency(self):
        """Test that djb2_hash produces consistent results"""
        text = "Hello, World!"
        result1 = Hasher.djb2_hash(text)
        result2 = Hasher.djb2_hash(text)
        assert result1 == result2

    def test_djb2_hash_32bit(self):
        """Test that djb2_hash stays within 32-bit range"""
        long_text = "a" * 1000
        result = Hasher.djb2_hash(long_text)
        assert result <= 0xFFFFFFFF

    def test_builtin_hash_basic(self):
        """Test basic functionality of builtin_hash"""
        result = Hasher.builtin_hash("test")
        assert isinstance(result, int)

    def test_builtin_hash_consistency(self):
        """Test that builtin_hash produces consistent results in same session"""
        text = "Hello, World!"
        result1 = Hasher.builtin_hash(text)
        result2 = Hasher.builtin_hash(text)
        assert result1 == result2

    def test_crypto_hash_sha256_default(self):
        """Test crypto_hash with default SHA256"""
        result = Hasher.crypto_hash("test")
        assert isinstance(result, str)
        assert len(result) == 64  # SHA256 produces 64 character hex string

    def test_crypto_hash_md5(self):
        """Test crypto_hash with MD5"""
        result = Hasher.crypto_hash("test", "md5")
        assert isinstance(result, str)
        assert len(result) == 32  # MD5 produces 32 character hex string

    def test_crypto_hash_sha1(self):
        """Test crypto_hash with SHA1"""
        result = Hasher.crypto_hash("test", "sha1")
        assert isinstance(result, str)
        assert len(result) == 40  # SHA1 produces 40 character hex string

    def test_crypto_hash_consistency(self):
        """Test that crypto_hash produces consistent results"""
        text = "Hello, World!"
        result1 = Hasher.crypto_hash(text)
        result2 = Hasher.crypto_hash(text)
        assert result1 == result2

    def test_crypto_hash_known_values(self):
        """Test crypto_hash with known test vectors"""
        # Known SHA256 hash of "test"
        expected_sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        result = Hasher.crypto_hash("test", "sha256")
        assert result == expected_sha256

    def test_empty_string_handling(self):
        """Test all hash functions with empty string"""
        empty = ""

        simple_result = Hasher.simple_hash(empty)
        assert simple_result == 0  # Empty string should hash to 0

        djb2_result = Hasher.djb2_hash(empty)
        assert djb2_result == 5381  # DJB2 initial value

        builtin_result = Hasher.builtin_hash(empty)
        assert isinstance(builtin_result, int)

        crypto_result = Hasher.crypto_hash(empty)
        assert isinstance(crypto_result, str)


class TestHashTable:
    """Test cases for the HashTable class"""

    def test_hash_table_creation(self):
        """Test HashTable initialization"""
        ht = HashTable()
        assert ht.size == 100
        assert len(ht.table) == 100

    def test_hash_table_custom_size(self):
        """Test HashTable with custom size"""
        ht = HashTable(50)
        assert ht.size == 50
        assert len(ht.table) == 50

    def test_put_and_get(self):
        """Test basic put and get operations"""
        ht = HashTable(10)
        ht.put("key1", "value1")
        assert ht.get("key1") == "value1"

    def test_put_update_existing(self):
        """Test updating existing key"""
        ht = HashTable(10)
        ht.put("key1", "value1")
        ht.put("key1", "value2")
        assert ht.get("key1") == "value2"

    def test_get_nonexistent_key(self):
        """Test getting nonexistent key raises KeyError"""
        ht = HashTable(10)
        with pytest.raises(KeyError):
            ht.get("nonexistent")

    def test_remove_existing_key(self):
        """Test removing existing key"""
        ht = HashTable(10)
        ht.put("key1", "value1")
        ht.remove("key1")
        with pytest.raises(KeyError):
            ht.get("key1")

    def test_remove_nonexistent_key(self):
        """Test removing nonexistent key raises KeyError"""
        ht = HashTable(10)
        with pytest.raises(KeyError):
            ht.remove("nonexistent")

    def test_collision_handling(self):
        """Test that hash table handles collisions properly"""
        ht = HashTable(2)  # Small size to force collisions

        # Add multiple items that may collide
        ht.put("key1", "value1")
        ht.put("key2", "value2")
        ht.put("key3", "value3")

        # All should be retrievable
        assert ht.get("key1") == "value1"
        assert ht.get("key2") == "value2"
        assert ht.get("key3") == "value3"

    def test_different_key_types(self):
        """Test hash table with different key types"""
        ht = HashTable(10)

        ht.put("string_key", "value1")
        ht.put(123, "value2")
        ht.put((1, 2), "value3")

        assert ht.get("string_key") == "value1"
        assert ht.get(123) == "value2"
        assert ht.get((1, 2)) == "value3"

    def test_large_dataset(self):
        """Test hash table with larger dataset"""
        ht = HashTable(100)

        # Add 200 items to test collision handling
        for i in range(200):
            ht.put(f"key{i}", f"value{i}")

        # Verify all items can be retrieved
        for i in range(200):
            assert ht.get(f"key{i}") == f"value{i}"

        # Test removal
        ht.remove("key50")
        with pytest.raises(KeyError):
            ht.get("key50")

        # Verify other items still exist
        assert ht.get("key49") == "value49"
        assert ht.get("key51") == "value51"