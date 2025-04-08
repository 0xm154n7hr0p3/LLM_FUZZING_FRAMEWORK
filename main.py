#!/usr/bin/env python3
#main.py
import argparse
import json
import logging
import os
import banner
from colorama import Fore, Back, Style, init
init()
#from src.vulnerabilities.prompt_injection import PromptInjectionFuzzer
from src.vulnerabilities.system_prompt_leakage.system_prompt_leakage import SystemPromptLeakageFuzzer
from src.vulnerabilities.unbounded_consumption.unbounded_consumption import UnboundedConsumptionFuzzer

#from src.base_fuzzer import BaseFuzzer
from utils.request_handler import RequestHandler
# ResultAnalyzer import removed

# Update the vulnerability fuzzers dictionary
VULNERABILITY_FUZZERS = {
#    'insecure_output_handling': InsecureOutputHandlingFuzzer,
#    'excessive_agency': ExcessiveAgencyFuzzer,
    'system_prompt_leakage': SystemPromptLeakageFuzzer,
#    'vector_embedding_weaknesses': VectorEmbeddingWeaknessesFuzzer,
#    'misinformation': MisinformationFuzzer,
    'unbounded_consumption': UnboundedConsumptionFuzzer,
#    'prompt_injection': PromptInjectionFuzzer,
#    'sensitive_information_disclosure': SensitiveInformationDisclosureFuzzer
}

def setup_logging(log_file: str, log_level: str) -> logging.Logger:
    """
    Configure and setup logging for the application.
    
    :param log_file: Path to the log file
    :param log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    :return: Configured logger object
    """
    # Create logger
    logger = logging.getLogger('LLMFuzzer')
    
    # Convert log level string to logging constant
    log_level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    numeric_level = log_level_map.get(log_level.upper(), logging.INFO)
    
    # Set logger's log level
    logger.setLevel(numeric_level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create file handler
    try:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(numeric_level)
        logger.addHandler(file_handler)
    except IOError as e:
        print(f"Error creating log file: {e}")
        # Fallback to console logging if file handler fails
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(numeric_level)
        logger.addHandler(console_handler)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(numeric_level)
    logger.addHandler(console_handler)
    
    return logger

def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure argument parser for the LLM fuzzer.
    
    :return: Configured ArgumentParser object
    """
    parser = argparse.ArgumentParser(
        description='LLM API Vulnerability Fuzzer - Test LLM security with OWASP TOP 10',
        epilog='Example: python main.py -e https://api.example.com/generate -v prompt_injection -R req.txt '
    )
    
    parser.add_argument(
        '-e', '--endpoint', 
        type=str, 
        required=True, 
        help='LLM API endpoint URL'
    )
    
    parser.add_argument(
        '-v', '--vulnerability', 
        type=str, 
        choices=list(VULNERABILITY_FUZZERS.keys()),
        required=True, 
        help='Specific vulnerability to test'
    )
    
    parser.add_argument(
        '-o', '--output', 
        type=str, 
        default='fuzzer_results.json', 
        help='Output file for fuzzing results (default: fuzzer_results.json)'
    )
    
    parser.add_argument(
        '-l', '--log-file', 
        type=str, 
        default='fuzzer_logs.log', 
        help='Log file path (default: fuzzer_logs.log)'
    )
    
    parser.add_argument(
        '--log-level', 
        type=str, 
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO', 
        help='Set the logging level (default: INFO)'
    )
    
    parser.add_argument(
        '--max-payloads', 
        type=int, 
        default=None, 
        help='Limit the number of payloads to test (optional)'
    )
    
    parser.add_argument(
        '-H', '--headers', 
        type=str, 
        default=None, 
        help='Add headers to the request as JSON, e.g. \'{"Cookie": "yk=value"}\''
    )
    
    parser.add_argument(
        '-R', '--raw-request', 
        type=str,
        required=True,
        help='Path to file containing raw HTTP request'
    )
    
    # Optional arguments for custom payload and indicator files
    parser.add_argument(
        '--payload-file', 
        type=str, 
        help='Custom payload file for the selected vulnerability'
    )
    
    parser.add_argument(
        '--success-indicators', 
        type=str, 
        help='Custom success indicators file'
    )
    
    parser.add_argument(
        '--failure-indicators', 
        type=str, 
        help='Custom failure indicators file'
    )
    
    parser.add_argument(
        '--response-field',
        type=str,
        required=True,
        help='Field to extract from JSON responses'
    )
    parser.add_argument(
        '--max_token_threshold',
        type=int,
        default=5000,
        help='Maximum amount of tokens LLM should not bypass when producing output. Default = 5000'
    )
    parser.add_argument(
        '--rate_limit_test_count',
        type=int,
        default=15,
        help='Number of requests for rate limit testing. Default = 15'
    )
    parser.add_argument(
        '--rate_limit_interval',
        type=float,
        default=0.1,
        help='Time between requests for rate limit testing (seconds). Default = 0.1' )
    return parser

def run_fuzzer(
    endpoint: str, 
    vulnerability: str, 
    output_file: str, 
    max_payloads: int = None,
    raw_request_file: str = None,
    payload_file: str = None,
    success_indicators_file: str = None,
    failure_indicators_file: str = None,
    max_token_threshold: int = None,
    rate_limit_test_count: int= None ,  
    rate_limit_interval: float= None ,
    response_field: str = None
) -> dict:
    """
    Run the specified vulnerability fuzzer.
    
    :param endpoint: LLM API endpoint
    :param vulnerability: Vulnerability type to test
    :param output_file: File to save results
    :param max_payloads: Optional limit on number of payloads
    :param raw_request_file: Optional raw HTTP request template file
    :param payload_file: Optional custom payload file
    :param success_indicators_file: Optional success indicators file
    :param failure_indicators_file: Optional failure indicators file
    :param response_field: Optional specific field to extract from JSON response
    :return: Fuzzing results
    """
    # Initialize request handler
    request_handler = RequestHandler(raw_request_file=raw_request_file)
    
    # Get the appropriate fuzzer class
    fuzzer_class = VULNERABILITY_FUZZERS[vulnerability]
    
    # Create fuzzer instance with updated parameters
    fuzzer_kwargs = {
        'model_endpoint': endpoint,
        'request_handler': request_handler,
        'response_field': response_field
  # Now directly passed to the fuzzer
    }
    # Special arguments for the vulnerabilty Unbounded Consumption
    if fuzzer_class == UnboundedConsumptionFuzzer:
        fuzzer_kwargs['max_token_threshold']= max_token_threshold
        fuzzer_kwargs['rate_limit_test_count']= rate_limit_test_count
        fuzzer_kwargs['rate_limit_interval']= rate_limit_interval
    
    # Add optional parameters if provided
    if payload_file:
        fuzzer_kwargs['payload_file'] = payload_file
    if success_indicators_file:
        fuzzer_kwargs['success_indicators_file'] = success_indicators_file
    if failure_indicators_file:
        fuzzer_kwargs['failure_indicators_file'] = failure_indicators_file
    
    # Create fuzzer instance
    fuzzer = fuzzer_class(**fuzzer_kwargs)

    # Potentially limit payloads
    if max_payloads is not None:
        fuzzer.payloads = fuzzer.payloads[:max_payloads]

    # Run fuzzing
    global logger  # Use the global logger
    logger.info(f"Starting fuzzing for {vulnerability} vulnerability")
    results = fuzzer.fuzz()

    # Save results to file
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {output_file}")
    except IOError as e:
        logger.error(f"Failed to write results: {e}")

    return results


def main():
    """
    Main entry point for the LLM Fuzzer application.
    Parses arguments and orchestrates fuzzing process.
    """
    # Parse command-line arguments
    banner.banner()
    banner.title()

    parser = create_argument_parser()
    args = parser.parse_args()

    # Setup global logger
    global logger
    logger = setup_logging(args.log_file, args.log_level)

    try:
        
        # Run the fuzzer
        results = run_fuzzer(
            endpoint=args.endpoint,
            vulnerability=args.vulnerability,
            output_file=args.output,
            max_payloads=args.max_payloads,
            raw_request_file=args.raw_request,
            payload_file=args.payload_file,
            success_indicators_file=args.success_indicators,
            failure_indicators_file=args.failure_indicators,
            max_token_threshold=args.max_token_threshold,
            rate_limit_test_count= args.rate_limit_test_count,
            rate_limit_interval= args.rate_limit_interval,
            response_field=args.response_field
        )

        # Display results using the fuzzer's display method
        fuzzer_class = VULNERABILITY_FUZZERS[args.vulnerability]
        fuzzer = fuzzer_class(
            model_endpoint=args.endpoint,
            request_handler=RequestHandler(raw_request_file=args.raw_request),
            response_field=args.response_field
        )
        fuzzer.display_results(results, args.response_field)

    except Exception as e:
        logger.error(f"Fuzzing failed: {e}")
        raise

if __name__ == "__main__":
    main()