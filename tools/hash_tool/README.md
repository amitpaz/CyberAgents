# Hash Tool

## Tool Information

**Name**: Hash Tool

**Version**: 1.0.0

**Author**: CyberAgents Team

**Category**: Cryptography/File Analysis

**Description**:
The Hash Tool is a versatile utility designed to generate cryptographic hash values for files, strings, or binary data. It supports multiple hashing algorithms including MD5, SHA-1, SHA-256, SHA-384, and SHA-512. Hash values serve as digital fingerprints that uniquely identify data, making this tool essential for file integrity verification, malware identification, password storage, and digital forensics investigations.

## Prerequisites

- Python 3.8+
- Required packages: hashlib (built-in)
- External dependencies: None

## Installation

No additional packages need to be installed as this tool utilizes Python's built-in hashlib module.

## Configuration

### Required Configuration

No specific configuration is required for this tool.

### Optional Configuration

- `algorithm`: Specify the hashing algorithm to use (default: SHA-256)
- `compare_hash`: Optional hash value to compare against the computed hash

## Usage

### Basic Usage

Initialize the tool and generate hash values for strings or files by specifying the input and desired hashing algorithm.

### Advanced Usage

Verify file integrity by comparing computed hash values against known good values, or batch process multiple files to generate hash lists for documentation or verification purposes.

## Integration with Agents

This tool can be integrated with CrewAI agents as part of a digital forensics workflow to verify file integrity or identify known malicious files by their hash signatures.

## Command Line Interface

The tool provides hashing functionality through a simple interface for processing inputs.

### Running Locally

You can run the Hash Tool directly using the following commands:

```bash
# Generate hash for a string
poetry run python -m tools.hash_tool.hash_tool --input_data "Hello, World!" --is_file false --algorithm sha256

# Generate hash for a file
poetry run python -m tools.hash_tool.hash_tool --input_data path/to/file.txt --is_file true --algorithm sha256

# Compare with expected hash
poetry run python -m tools.hash_tool.hash_tool --input_data path/to/file.txt --is_file true --algorithm sha256 --compare_hash "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"

# Use different algorithm (MD5, SHA-1, SHA-256, SHA-384, SHA-512)
poetry run python -m tools.hash_tool.hash_tool --input_data "Hello, World!" --algorithm md5
```

For standard command-line hashing utilities:

```bash
# Using md5sum (Linux/macOS)
md5sum file.txt

# Using shasum (Linux/macOS)
shasum -a 256 file.txt
shasum -a 512 file.txt

# Using certutil (Windows)
certutil -hashfile file.txt MD5
certutil -hashfile file.txt SHA256

# Generate hash of a string using OpenSSL
echo -n "Hello, World!" | openssl dgst -md5
echo -n "Hello, World!" | openssl dgst -sha256

# Verify a file against a known hash
echo "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e file.txt" | shasum -a 256 -c
```

## API Reference

### Main Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `_run()` | input_data (str), is_file (bool), algorithm (str), compare_hash (str) | Dict\[str, Any\] | Generates hash values synchronously |
| `_arun()` | input_data (str), is_file (bool), algorithm (str), compare_hash (str) | Dict\[str, Any\] | Generates hash values asynchronously |

### Data Models

#### HashInput

Input model accepting parameters for:

- input_data: String or file path to hash
- is_file: Boolean indicating if input_data is a file path
- algorithm: Hashing algorithm to use (MD5, SHA-1, SHA-256, SHA-384, SHA-512)
- compare_hash: Optional hash to compare with the computed hash

#### Return Format

Returns a dictionary containing:

- hash_value: The computed hash value
- algorithm: The algorithm used
- match: Boolean indicating if the computed hash matches the compare_hash (if provided)
- error: Any error message (if applicable)

## Error Handling

Handle errors by checking for the presence of an "error" key in the results dictionary returned by the tool.

## Best Practices

1. **Algorithm Selection**: Use SHA-256 or stronger for security-sensitive applications
1. **Performance Considerations**: For large files, consider streaming approaches rather than loading the entire file into memory
1. **Validation**: Always validate inputs, especially when processing file paths
1. **Security Awareness**: Remember that while MD5 and SHA-1 are faster, they are no longer considered cryptographically secure
1. **Comparison Safety**: Use constant-time comparison when comparing hashes in security-critical applications

## Troubleshooting

### Common Issues

1. **File Access Errors**

   - Ensure the tool has proper permissions to read the specified files
   - Verify file paths are correct and files exist

1. **Algorithm Selection**

   - Verify that the specified algorithm is supported
   - Be aware of performance implications for large files with different algorithms

1. **Encoding Issues**

   - When hashing strings, be consistent with character encoding (UTF-8 recommended)
   - Hash binary data directly rather than converting to strings when possible

## Changelog

### v1.0.0 (2023-12-01)

- Initial release
- Support for MD5, SHA-1, SHA-256, SHA-384, and SHA-512 algorithms
- File and string hashing capabilities
- Hash comparison functionality
- Integration with CrewAI

## License

MIT License

## Contact

For support, feature requests, or bug reports, please contact:

- GitHub: [CyberAgents Repository](https://github.com/your-org/cyberagents)
