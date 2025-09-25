import hashlib

class Hasher:
    """
    A collection of hash functions for various use cases
    """

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

    @staticmethod
    def file_hash(file_path, algorithm='sha256', output_format='hex'):
        """
        Generate hash of a file

        Args:
            file_path (str): Path to the file to hash
            algorithm (str): Hash algorithm ('sha256' or 'md5')
            output_format (str): Output format ('hex' or 'text')

        Returns:
            str: Hash value in the specified format
        """
        if algorithm.lower() not in ['sha256', 'md5']:
            raise ValueError("Algorithm must be 'sha256' or 'md5'")

        if output_format.lower() not in ['hex', 'text']:
            raise ValueError("Output format must be 'hex' or 'text'")

        hash_obj = hashlib.new(algorithm.lower())

        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {file_path}")
        except PermissionError:
            raise PermissionError(f"Permission denied: {file_path}")

        if output_format.lower() == 'hex':
            return hash_obj.hexdigest()
        else:  # text format - return base64 encoded
            import base64
            return base64.b64encode(hash_obj.digest()).decode('utf-8')
