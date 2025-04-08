# Metadata Extractor Tool

## Tool Information

**Name**: Metadata Extractor Tool

**Version**: 1.0.0

**Author**: CyberAgents Team

**Category**: Forensics/Information Gathering

**Description**:
The Metadata Extractor Tool is designed to extract and analyze hidden metadata from various file types, including images, documents, PDFs, and more. Metadata often contains valuable information such as creation dates, author details, GPS coordinates (for images), software used, and revision history. This tool helps security professionals gather intelligence from files during investigations, exposing information that may not be visible to the casual observer and providing important context during security assessments.

## Prerequisites

- Python 3.8+
- Required packages: exifread, python-docx, PyPDF2, pillow
- External dependencies: None

## Installation

Install the required packages using Poetry.

```bash
poetry add exifread python-docx PyPDF2 pillow
```

## Configuration

### Required Configuration

No specific configuration is required for this tool.

### Optional Configuration

- `extract_all`: Boolean flag to extract all available metadata (default: true)
- `specific_fields`: List of specific metadata fields to extract when extract_all is false

## Usage

### Basic Usage

Initialize the tool and extract metadata from a file by providing the file path to discover hidden information about the file's origin and properties.

### Advanced Usage

Filter extraction to specific metadata fields of interest, or process multiple files in batch mode to compare metadata across a collection of related files.

## Integration with Agents

This tool can be integrated with CrewAI agents as part of a digital forensics workflow to extract and analyze metadata from files collected during investigations.

## Command Line Interface

The tool provides metadata extraction functionality through a file processing interface.

### Running Locally

You can run the Metadata Extractor Tool directly using the following commands:

```bash
# Extract all metadata from a file
poetry run python -m tools.metadata_extractor.metadata_tool --file_path path/to/image.jpg

# Extract specific metadata fields
poetry run python -m tools.metadata_extractor.metadata_tool --file_path path/to/document.docx --extract_all false --specific_fields "author,created,modified"

# Output results to a JSON file
poetry run python -m tools.metadata_extractor.metadata_tool --file_path path/to/file.pdf --output results.json
```

For alternative command-line metadata extraction:

```bash
# Using exiftool (if installed)
# Install on Ubuntu/Debian
sudo apt-get install libimage-exiftool-perl

# Install on macOS
brew install exiftool

# Basic usage
exiftool path/to/image.jpg

# Extract specific tags
exiftool -Author -CreateDate path/to/document.pdf

# Output in JSON format
exiftool -j path/to/file.png

# Using Linux file command for basic metadata
file path/to/file.jpg

# Using pdfinfo for PDF files
pdfinfo document.pdf
```

## API Reference

### Main Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `_run()` | file_path (str), extract_all (bool), specific_fields (List\[str\]) | Dict\[str, Any\] | Extracts metadata from a file synchronously |
| `_arun()` | file_path (str), extract_all (bool), specific_fields (List\[str\]) | Dict\[str, Any\] | Extracts metadata from a file asynchronously |

### Data Models

#### MetadataExtractorInput

Input model accepting parameters for:

- file_path: Path to the file for metadata extraction
- extract_all: Boolean indicating whether to extract all metadata
- specific_fields: List of specific metadata fields to extract when extract_all is false

#### Return Format

Returns a dictionary containing extracted metadata mapped by category and field name, with an optional error field if issues occurred during extraction.

## Error Handling

Handle errors by checking for the presence of an "error" key in the results dictionary returned by the tool.

## Best Practices

1. **Privacy Awareness**: Be aware that metadata may contain sensitive personal information
1. **File Type Support**: Verify that the file type is supported before attempting extraction
1. **Large Files**: For large files, consider processing in chunks to avoid memory issues
1. **Validation**: Validate extracted metadata as some fields may be intentionally falsified
1. **Comprehensive Analysis**: Cross-reference metadata across multiple files for more complete intelligence

## Troubleshooting

### Common Issues

1. **Unsupported File Types**

   - Check file extensions and file signatures
   - Consider using file type detection libraries

1. **Missing Metadata**

   - Some files may have metadata stripped or never contained it
   - Try alternative extraction methods or tools for specialized formats

1. **Encoding Issues**

   - Metadata may use various character encodings
   - Implement proper encoding detection and handling

## Changelog

### v1.0.0 (2023-12-01)

- Initial release
- Support for common file formats (JPEG, PNG, PDF, DOCX)
- Extraction of standard and extended metadata fields
- Integration with CrewAI

## License

MIT License

## Contact

For support, feature requests, or bug reports, please contact:

- GitHub: [CyberAgents Repository](https://github.com/your-org/cyberagents)
