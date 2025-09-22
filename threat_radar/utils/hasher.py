import hashlib

class Hasher:
    """
    A collection of hash functions for various use cases
    """

    @staticmethod
    def simple_hash(text, table_size=1000):
        """
        Simple polynomial rolling hash function
        Uses base 31 (a prime number) for better distribution
        """
        hash_value = 0
        base = 31

        for char in text:
            hash_value = (hash_value * base + ord(char)) % table_size

        return hash_value

    @staticmethod
    def djb2_hash(text):
        """
        DJB2 hash algorithm by Dan Bernstein
        Known for good distribution properties
        """
        hash_value = 5381

        for char in text:
            hash_value = ((hash_value << 5) + hash_value) + ord(char)
            hash_value &= 0xFFFFFFFF  # Keep it 32-bit

        return hash_value

    @staticmethod
    def builtin_hash(text):
        """
        Uses Python's built-in hash() function
        Note: This can vary between Python runs due to hash randomization
        """
        return hash(text)

    @staticmethod
    def crypto_hash(text, algorithm='sha256'):
        """
        Cryptographic hash using hashlib
        Algorithms: md5, sha1, sha256, sha512, etc.
        """
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(text.encode('utf-8'))
        return hash_obj.hexdigest()


class HashTable:
    """Hash table implementation using the Hasher class"""

    def __init__(self, size=100):
        self.size = size
        self.table = [[] for _ in range(size)]

    def _hash(self, key):
        return Hasher.simple_hash(str(key), self.size)

    def put(self, key, value):
        hash_index = self._hash(key)
        bucket = self.table[hash_index]

        for i, (k, v) in enumerate(bucket):
            if k == key:
                bucket[i] = (key, value)
                return

        bucket.append((key, value))

    def get(self, key):
        hash_index = self._hash(key)
        bucket = self.table[hash_index]

        for k, v in bucket:
            if k == key:
                return v

        raise KeyError(key)

    def remove(self, key):
        hash_index = self._hash(key)
        bucket = self.table[hash_index]

        for i, (k, v) in enumerate(bucket):
            if k == key:
                del bucket[i]
                return

        raise KeyError(key)