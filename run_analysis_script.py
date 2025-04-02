import asyncio
from main import DomainIntelligenceCrew
import json
import logging
import sys

# Suppress logs below ERROR to avoid cluttering the output
logging.getLogger().setLevel(logging.ERROR)

async def analyze():
    # Get domain from command-line argument or use default
    domain = sys.argv[1] if len(sys.argv) > 1 else "www.walla.co.il"
    print(f"Analyzing domain: {domain}...", flush=True)
    crew = DomainIntelligenceCrew()
    try:
        results = await crew.analyze_domain(domain)
        print("Analysis complete.", flush=True)
        # Pretty print the JSON output
        print(json.dumps(results, indent=2, default=str)) # Use default=str for non-serializable types like datetime
    except Exception as e:
        print(f"An error occurred during analysis: {e}", file=sys.stderr)
        # Print traceback for more details
        import traceback
        traceback.print_exc()
        sys.exit(1) # Exit with error code

if __name__ == "__main__":
    asyncio.run(analyze()) 