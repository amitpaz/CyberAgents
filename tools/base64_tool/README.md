## Command Line Interface

The tool provides encoding and decoding functionality through a simple interface.

### Running Locally

You can run the Base64 Encoder/Decoder Tool directly using the following commands:

```bash
# Encode a string to Base64
poetry run python -m tools.base64_tool.base64_tool --input_string "Hello, World!" --operation encode

# Decode a Base64 string
poetry run python -m tools.base64_tool.base64_tool --input_string "SGVsbG8sIFdvcmxkIQ==" --operation decode

# Encode contents of a file
poetry run python -m tools.base64_tool.base64_tool --input_string "path/to/file.txt" --operation encode --is_file

# Decode Base64 to a file
poetry run python -m tools.base64_tool.base64_tool --input_string "SGVsbG8sIFdvcmxkIQ==" --operation decode --output_file output.txt
```

You can also use built-in command-line tools for Base64 encoding/decoding:

```bash
# Using base64 command (Linux/macOS)
# Encode
echo -n "Hello, World!" | base64

# Decode
echo -n "SGVsbG8sIFdvcmxkIQ==" | base64 -d

# Encode a file
base64 file.txt > file.txt.b64

# Decode to a file
base64 -d file.txt.b64 > file.txt

# On Windows using PowerShell
# Encode
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Hello, World!"))

# Decode
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("SGVsbG8sIFdvcmxkIQ=="))
```
