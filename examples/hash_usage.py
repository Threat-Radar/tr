#!/usr/bin/env python3
"""
Hash CLI Usage Example

This example demonstrates how to use the threat-radar hash functionality
to generate file hashes with different algorithms and output formats.

Usage:
    python examples/hash_usage.py

Requirements:
    - threat-radar package with dependencies
    - Python 3.8+
"""

import os
import sys
import tempfile

# Add the project root to the Python path so we can import threat_radar
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from threat_radar.utils.hasher import Hasher


def create_sample_files():
    """Create sample files for hashing demonstration"""

    # Create a temporary directory for our examples
    temp_dir = tempfile.mkdtemp(prefix="hash_examples_")

    # Sample text file
    text_file = os.path.join(temp_dir, "sample.txt")
    with open(text_file, "w") as f:
        f.write("Hello, World!\nThis is a sample text file for hashing.\n")

    # Sample binary file (simple binary data)
    binary_file = os.path.join(temp_dir, "sample.bin")
    with open(binary_file, "wb") as f:
        f.write(b'\x00\x01\x02\x03\x04\x05\xff\xfe\xfd')

    # Sample configuration file
    config_file = os.path.join(temp_dir, "config.json")
    with open(config_file, "w") as f:
        f.write('{\n  "version": "1.0",\n  "debug": true\n}\n')

    return temp_dir, [text_file, binary_file, config_file]


def hash_file_example(file_path, algorithm="sha256", output_format="hex"):
    """Generate hash using the Hasher class directly"""
    try:
        result = Hasher.file_hash(file_path, algorithm, output_format)
        return f"{algorithm.upper()} ({output_format}): {result}"
    except Exception as e:
        return f"Error: {e}"


def main():
    """Main example function"""

    print("=" * 60)
    print("Threat Radar CLI Hash Usage Examples")
    print("=" * 60)
    print()

    # Create sample files
    temp_dir, sample_files = create_sample_files()

    try:
        # Example 1: Basic SHA256 hash (default)
        print("1. Basic SHA256 Hash (default settings)")
        print("-" * 40)
        text_file = sample_files[0]
        result = hash_file_example(text_file)
        print(f"File: {os.path.basename(text_file)}")
        print(f"CLI Command: python -m threat_radar.cli hash file {text_file}")
        print(f"Result: {result}")
        print()

        # Example 2: MD5 hash with hex output
        print("2. MD5 Hash with Hex Output")
        print("-" * 40)
        result = hash_file_example(text_file, "md5", "hex")
        print(f"File: {os.path.basename(text_file)}")
        print(f"CLI Command: python -m threat_radar.cli hash file {text_file} --algorithm md5 --format hex")
        print(f"Result: {result}")
        print()

        # Example 3: SHA256 with text (base64) output
        print("3. SHA256 Hash with Text (Base64) Output")
        print("-" * 40)
        result = hash_file_example(text_file, "sha256", "text")
        print(f"File: {os.path.basename(text_file)}")
        print(f"CLI Command: python -m threat_radar.cli hash file {text_file} --algorithm sha256 --format text")
        print(f"Result: {result}")
        print()

        # Example 4: Hashing a binary file
        print("4. Hashing a Binary File")
        print("-" * 40)
        binary_file = sample_files[1]
        result = hash_file_example(binary_file, "sha256", "hex")
        print(f"File: {os.path.basename(binary_file)}")
        print(f"CLI Command: python -m threat_radar.cli hash file {binary_file} --algorithm sha256 --format hex")
        print(f"Result: {result}")
        print()

        # Example 5: Using MD5 with text output
        print("5. MD5 with Text (Base64) Output")
        print("-" * 40)
        config_file = sample_files[2]
        result = hash_file_example(config_file, "md5", "text")
        print(f"File: {os.path.basename(config_file)}")
        print(f"CLI Command: python -m threat_radar.cli hash file {config_file} -a md5 -f text")
        print(f"Result: {result}")
        print()

        # Example 6: Compare different algorithms on same file
        print("6. Comparing Different Algorithms")
        print("-" * 40)
        print(f"File: {os.path.basename(text_file)}")
        print("SHA256:", hash_file_example(text_file, "sha256", "hex").split(": ", 1)[1])
        print("MD5:   ", hash_file_example(text_file, "md5", "hex").split(": ", 1)[1])
        print()

        # Example 7: Error handling - non-existent file
        print("7. Error Handling - Non-existent File")
        print("-" * 40)
        non_existent = "/tmp/non_existent_file.txt"
        result = hash_file_example(non_existent)
        print(f"CLI Command: python -m threat_radar.cli hash file {non_existent}")
        print(f"Result: {result}")
        print()

        # Example 8: Programmatic usage
        print("8. Programmatic Usage")
        print("-" * 40)
        print("You can also use the Hasher class directly in your Python code:")
        print()
        print("from threat_radar.utils.hasher import Hasher")
        print()
        print("# Generate SHA256 hash")
        print(f"hash_value = Hasher.file_hash('{os.path.basename(text_file)}', 'sha256', 'hex')")
        result = Hasher.file_hash(text_file, 'sha256', 'hex')
        print(f"# Result: {result}")
        print()
        print("# Generate MD5 hash in base64 format")
        print(f"hash_value = Hasher.file_hash('{os.path.basename(text_file)}', 'md5', 'text')")
        result = Hasher.file_hash(text_file, 'md5', 'text')
        print(f"# Result: {result}")
        print()

        print("=" * 60)
        print("Available Options:")
        print("  --algorithm, -a: sha256 (default) or md5")
        print("  --format, -f:    hex (default) or text")
        print("=" * 60)
        print()
        print("Use Cases:")
        print("• File integrity verification")
        print("• Security auditing")
        print("• Change detection")
        print("• Duplicate file identification")
        print("• Forensic analysis")

    finally:
        # Clean up temporary files
        import shutil
        shutil.rmtree(temp_dir)
        print(f"\nTemporary files cleaned up from: {temp_dir}")


if __name__ == "__main__":
    main()