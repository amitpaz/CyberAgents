# Text Analysis Tool

## Tool Information

**Name**: Text Analysis Tool

**Version**: 1.0.0

**Author**: CyberAgents Team

**Category**: Content Analysis/Natural Language Processing

**Description**:
The Text Analysis Tool is a utility for performing advanced linguistic and semantic analysis on textual content. It offers capabilities for sentiment analysis, entity recognition, topic extraction, language detection, and readability assessment. This tool helps security professionals analyze large volumes of text data to identify potentially malicious content, extract valuable intelligence, assess communication patterns, and understand the context and sentiment of communications in security investigations.

## Prerequisites

- Python 3.8+
- Required packages: nltk, spacy, textblob
- External dependencies: NLTK and spaCy language models

## Installation

Install the required packages using Poetry.

```bash
poetry add nltk spacy textblob
```

After installation, download the required language models:

```bash
python -m spacy download en_core_web_sm
python -m nltk.downloader punkt vader_lexicon stopwords
```

## Configuration

### Required Configuration

No specific configuration is required for this tool.

### Optional Configuration

- `language`: The language of the text to analyze (default: 'en')
- `analysis_types`: List of analysis types to perform (sentiment, entities, topics, readability)
- `max_length`: Maximum text length to process (default: 10000 characters)

## Usage

### Basic Usage

Initialize the tool and analyze text content by providing the text and specifying the types of analysis to perform (sentiment, entities, topics, readability).

### Advanced Usage

Customize analysis parameters for specific use cases, such as adjusting sentiment thresholds, specifying entity types to extract, or focusing on particular readability metrics for more targeted analysis.

## Integration with Agents

This tool can be integrated with CrewAI agents as part of a content analysis workflow to process and extract insights from textual data during security investigations or threat intelligence gathering.

## Command Line Interface

The tool provides text analysis functionality through a simple interface for processing textual content.

### Running Locally

You can run the Text Analysis Tool directly using the following commands:

```bash
# Basic text analysis with all analysis types
poetry run python -m tools.text_analysis.text_tool --text "This is a sample text for analysis"

# Specify analysis types to perform
poetry run python -m tools.text_analysis.text_tool --text "This is a sample text for analysis" --analysis_types "sentiment,entities"

# Analyze text in a different language
poetry run python -m tools.text_analysis.text_tool --text "C'est un exemple de texte pour l'analyse" --language fr

# Set maximum text length
poetry run python -m tools.text_analysis.text_tool --text "This is a sample text for analysis" --max_length 5000

# Analyze text from a file
poetry run python -m tools.text_analysis.text_tool --file path/to/text_file.txt

# Output results to a JSON file
poetry run python -m tools.text_analysis.text_tool --text "This is a sample text for analysis" --output results.json
```

For alternative text analysis from the command line:

```bash
# Using NLTK directly (if installed)
python -c "import nltk; from nltk.sentiment import SentimentIntensityAnalyzer; analyzer = SentimentIntensityAnalyzer(); print(analyzer.polarity_scores('This is a great example.'))"

# Using spaCy directly (if installed)
python -c "import spacy; nlp = spacy.load('en_core_web_sm'); doc = nlp('Apple is looking at buying a startup for $1 billion in the U.S.'); print([(ent.text, ent.label_) for ent in doc.ents])"

# Using textblob (if installed)
python -c "from textblob import TextBlob; blob = TextBlob('The food was excellent.'); print(blob.sentiment)"

# Process a text file with command-line tools
cat file.txt | python -c "import sys, spacy; nlp = spacy.load('en_core_web_sm'); doc = nlp(sys.stdin.read()); print([(ent.text, ent.label_) for ent in doc.ents])"
```

## API Reference

### Main Methods

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `_run()` | text (str), analysis_types (List\[str\]), language (str), max_length (int) | Dict\[str, Any\] | Performs text analysis synchronously |
| `_arun()` | text (str), analysis_types (List\[str\]), language (str), max_length (int) | Dict\[str, Any\] | Performs text analysis asynchronously |

### Data Models

#### TextAnalysisInput

Input model accepting parameters for:

- text: Text content to analyze
- analysis_types: List of analysis types to perform
- language: Language code of the text
- max_length: Maximum text length to process

#### Return Format

Returns a dictionary containing analysis results based on requested types:

- sentiment: Dictionary with polarity score and subjectivity
- entities: List of named entities with type and position
- topics: List of key topics and themes
- readability: Dictionary with various readability metrics
- language_detected: Detected language if different from specified
- error: Any error message (if applicable)

## Error Handling

Handle errors by checking for the presence of an "error" key in the results dictionary returned by the tool.

## Best Practices

1. **Text Preprocessing**: Clean and normalize text before analysis
1. **Language Specificity**: Use language-specific models for better accuracy
1. **Analysis Scope**: Limit analysis to relevant text segments for efficiency
1. **Context Awareness**: Consider the context when interpreting sentiment and entity results
1. **Verification**: Cross-verify automated analysis with human review for critical applications

## Troubleshooting

### Common Issues

1. **Language Model Errors**

   - Ensure required language models are properly downloaded
   - Verify compatibility between package versions and models
   - Consider using language-agnostic methods for multilingual content

1. **Processing Limitations**

   - Large texts may require chunking for efficient processing
   - Some analyses may timeout or use excessive resources on very large inputs
   - Consider pre-filtering or summarizing before analysis

1. **Accuracy Issues**

   - Domain-specific terminology may not be recognized correctly
   - Sarcasm and figurative language can affect sentiment accuracy
   - Consider training or fine-tuning models for specialized domains

## Changelog

### v1.0.0 (2023-12-01)

- Initial release
- Support for sentiment analysis, entity recognition, topic extraction
- Multilingual capabilities (primarily English)
- Readability assessment metrics
- Integration with CrewAI

## License

MIT License

## Contact

For support, feature requests, or bug reports, please contact:

- GitHub: [CyberAgents Repository](https://github.com/your-org/cyberagents)
