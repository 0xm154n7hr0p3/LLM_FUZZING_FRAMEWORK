import os
import datetime
import json
from typing import Dict, List, Optional, Union, Any
from colorama import Fore, Back, Style

class MisinformationFuzzer:
    def __init__(
        self, 
        model_endpoint, 
        request_handler, 
        tests_file=None,
        response_field=None
    ):
        """
        Initialize Misinformation Fuzzer with integrated analysis capabilities
        
        :param model_endpoint: LLM API endpoint
        :param request_handler: Request handling utility
        :param tests_file: Path to JSON file containing test cases
        :param response_field: JSON field to extract from response for analysis (e.g. "message")
        """
        self.model_endpoint = model_endpoint
        self.request_handler = request_handler
        self.response_field = response_field
        
        # For tracking matched indicators
        self._last_matched_success = []
        self._last_matched_failure = []
        
        # Default path in the same directory
        base_dir = os.path.dirname(__file__)
        default_tests_path = os.path.join(base_dir, './data/misinformation_payloads.json')
        print(default_tests_path)
        
        # Load test cases
        self.tests = self._load_tests(tests_file or default_tests_path)
    
    def _load_tests(self, file_path: str) -> List[Dict]:
        """
        Load test cases from a JSON file with error handling
        
        :param file_path: Path to tests JSON file
        :return: List of test dictionaries
        """
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                # Return the list of tests from the JSON structure
                return data.get("tests", [])
        except FileNotFoundError:
            print(f"Tests file not found: {file_path}")
            return []
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON in tests file: {e}")
            return []
        except Exception as e:
            print(f"Error reading tests file: {e}")
            return []

    def _extract_field_from_response(self, response: Any) -> str:
        """
        Extract a specific field from JSON response if specified.
        
        Args:
            response: API response (could be string or dict)
            
        Returns:
            Extracted field content or original response
        """
        if not self.response_field:
            return str(response)
            
        try:
            # If response is already a dict, use it directly
            if isinstance(response, dict):
                response_json = response
            else:
                # Parse response as JSON
                response_json = json.loads(response)
            
            # Extract the specified field
            if self.response_field in response_json:
                return str(response_json[self.response_field])
            else:
                print(f"Warning: Field '{self.response_field}' not found in response")
                return str(response)
        except json.JSONDecodeError:
            print(f"Warning: Response is not valid JSON, using full response")
            return str(response)
        except Exception as e:
            print(f"Error extracting field: {e}")
            return str(response)

    def check_success(self, response: str, success_indicators: List[str]) -> bool:
        """
        Check if response contains success indicators with stricter matching rules.
        
        :param response: LLM response text
        :param success_indicators: List of success indicators for this test
        :return: Whether vulnerability was successfully triggered
        """
        # Extract field if specified
        analyzed_text = self._extract_field_from_response(response)
        analyzed_text_lower = analyzed_text.lower()
        
        # Use word boundary matching to prevent partial word matches
        # For phrases, ensure the full phrase is present
        matched_indicators = []
        for indicator in success_indicators:
            indicator_lower = indicator.lower()
            # For multi-word phrases, check exact phrase
            if ' ' in indicator_lower:
                if indicator_lower in analyzed_text_lower:
                    matched_indicators.append(indicator)
            # For single words, check for word boundaries
            else:
                import re
                pattern = r'\b' + re.escape(indicator_lower) + r'\b'
                if re.search(pattern, analyzed_text_lower):
                    matched_indicators.append(indicator)
        
        # Store matched indicators for later analysis
        if matched_indicators:
            self._last_matched_success = matched_indicators
        
        return len(matched_indicators) > 0

    def check_failure(self, response: str, failure_indicators: List[str]) -> bool:
        """
        Check if response contains failure indicators with stricter matching rules.
        
        :param response: LLM response text
        :param failure_indicators: List of failure indicators for this test
        :return: Whether the attempt was blocked or failed
        """
        # Extract field if specified
        analyzed_text = self._extract_field_from_response(response)
        analyzed_text_lower = analyzed_text.lower()
        
        # Use word boundary matching to prevent partial word matches
        # For phrases, ensure the full phrase is present
        matched_indicators = []
        for indicator in failure_indicators:
            indicator_lower = indicator.lower()
            # For multi-word phrases, check exact phrase
            if ' ' in indicator_lower:
                if indicator_lower in analyzed_text_lower:
                    matched_indicators.append(indicator)
            # For single words, check for word boundaries
            else:
                import re
                pattern = r'\b' + re.escape(indicator_lower) + r'\b'
                if re.search(pattern, analyzed_text_lower):
                    matched_indicators.append(indicator)
        
        # Store matched indicators for later analysis
        if matched_indicators:
            self._last_matched_failure = matched_indicators
        
        return len(matched_indicators) > 0

    def analyze_response(
        self, 
        test_case: Dict,
        response: str
    ) -> Dict[str, Union[str, bool, List]]:
        """
        Comprehensive analysis of a single fuzzing response with stricter matching rules.
        
        :param test_case: The test case dictionary containing prompt and indicators
        :param response: LLM response to analyze
        :return: Detailed analysis of the response
        """
        # Reset matched indicators for this analysis
        self._last_matched_success = []
        self._last_matched_failure = []
        
        # Extract test components
        prompt = test_case["prompt"]
        
        # Support both old and new format
        success_indicators = test_case.get("success_matches", test_case.get("success_grep", []))
        failure_indicators = test_case.get("failure_matches", test_case.get("failure_grep", []))
        test_name = test_case.get("name", "Unnamed Test")
        
        # Extract field for analysis if specified
        analyzed_text = self._extract_field_from_response(response)
        
        # First check for failure indicators - these take precedence
        is_blocked = self.check_failure(response, failure_indicators)
        
        # Only check for success if no failure indicators were found
        is_successful = False
        if not is_blocked:
            is_successful = self.check_success(response, success_indicators)
        
        # Store analysis results
        analysis = {
            'test_name': test_name,
            'prompt': prompt,
            'full_response': response,
            'analyzed_text': analyzed_text,
            'is_successful': is_successful,
            'is_blocked': is_blocked,
            'success_indicators': success_indicators,
            'failure_indicators': failure_indicators
        }
        
        # Add matched indicators to the analysis
        if is_blocked:
            analysis['matched_indicators'] = self._last_matched_failure
        elif is_successful:
            analysis['matched_indicators'] = self._last_matched_success
        
        return analysis

    def aggregate_results(
        self, 
        individual_results: List[Dict]
    ) -> Dict:
        """
        Aggregate results from multiple fuzzing attempts.
        
        :param individual_results: List of individual test results
        :return: Categorized results
        """
        aggregated_results = {
            'total_tests': len(individual_results),
            'successful_exploits': [
                result for result in individual_results 
                if result['is_successful']
            ],
            'blocked_attempts': [
                result for result in individual_results 
                if result['is_blocked']
            ],
            'failed_attempts': [
                result for result in individual_results 
                if not result['is_successful'] and not result['is_blocked']
            ]
        }
        
        return aggregated_results
    
    def fuzz(self) -> Dict:
        """
        Perform comprehensive fuzzing for misinformation vulnerabilities
        
        :return: Detailed fuzzing results
        """
        # Prepare to collect individual test results
        individual_results = []
        
        # Tracking metadata for the entire fuzzing session
        fuzzing_metadata = {
            'start_time': datetime.datetime.now().isoformat(),
            'total_tests': len(self.tests),
            'endpoint': self.model_endpoint
        }
        
        # Run each test
        for test_case in self.tests:
            try:
                # Extract prompt from test case
                prompt = test_case["prompt"]
                
                # Send request with payload
                response = self.request_handler.send_request(
                    self.model_endpoint, 
                    prompt
                )
                
                # Analyze the response
                result_entry = self.analyze_response(
                    test_case=test_case,
                    response=response
                )
                
                # Add additional metadata to the result
                result_entry.update({
                    'timestamp': datetime.datetime.now().isoformat(),
                    'prompt_length': len(prompt),
                    'response_length': len(response)
                })
                
                individual_results.append(result_entry)
            
            except Exception as e:
                # Handle and log any errors during fuzzing
                error_entry = {
                    'test_name': test_case.get("name", "Unnamed Test"),
                    'prompt': test_case.get("prompt", ""),
                    'error': str(e),
                    'timestamp': datetime.datetime.now().isoformat(),
                    'is_successful': False,
                    'is_blocked': False
                }
                individual_results.append(error_entry)
        
        # Use integrated aggregation
        aggregated_results = self.aggregate_results(individual_results)
        
        # Add fuzzing metadata to the final results
        aggregated_results['fuzzing_metadata'] = fuzzing_metadata
        
        # Perform additional analysis
        aggregated_results['insights'] = self._generate_insights(aggregated_results)
        
        return aggregated_results
    
    def _generate_insights(self, results: Dict) -> Dict:
        """
        Generate additional insights from fuzzing results
        
        :param results: Aggregated fuzzing results
        :return: Insights dictionary
        """
        total_tests = results.get('total_tests', 0)
        
        insights = {
            'success_rate': len(results['successful_exploits']) / total_tests * 100 if total_tests > 0 else 0,
            'block_rate': len(results['blocked_attempts']) / total_tests * 100 if total_tests > 0 else 0,
            'most_revealing_tests': sorted(
                results['successful_exploits'], 
                key=lambda x: len(x.get('full_response', '')), 
                reverse=True
            )[:5] if results['successful_exploits'] else []  # Top 5 most revealing tests
        }
        
        return insights

    def display_results(self, results: Dict[str, Any], response_field: str = None) -> None:
        """
        Display fuzzing results with colored output and highlighting
        
        :param results: Fuzzing results dictionary
        """
        print("\n" + "="*80)
        print(f"{Fore.CYAN}MISINFORMATION FUZZING RESULTS{Style.RESET_ALL}")
        print("="*80)
        
        # Print colored summary to console
        vuln_status = f"{Fore.RED}VULNERABLE{Style.RESET_ALL}" if results.get("successful_exploits") else f"{Fore.GREEN}NOT VULNERABLE{Style.RESET_ALL}"
        print(f"\nOverall Status: {vuln_status}")
        print(f"Total tests run: {Fore.CYAN}{results.get('total_tests', 0)}{Style.RESET_ALL} \n")
        print(f"Successful exploits: {Fore.RED}{len(results.get('successful_exploits', []))}{Style.RESET_ALL}")
        print(f"Blocked attempts: {Fore.GREEN}{len(results.get('blocked_attempts', []))}{Style.RESET_ALL}")
        print(f"Failed attempts: {len(results.get('failed_attempts', []))}\n")

        # Print detailed successful exploits with highlighting
        if results.get('successful_exploits'):
            print(f"{Fore.YELLOW}=== Successful Exploits ==={"="*53}{Style.RESET_ALL}")
            for i, exploit in enumerate(results['successful_exploits'], 1):
                print(f"\n{Fore.RED}Exploit #{i}: {exploit.get('test_name', 'Unnamed Test')}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Prompt:{Style.RESET_ALL}\n{exploit['prompt']}")
                
                # Highlight matched indicators in the response
                if 'matched_indicators' in exploit:
                    indicators = exploit['matched_indicators']
                else:
                    indicators = exploit.get('success_indicators', [])
                
                # Show the analyzed text if a specific field was extracted
                if 'analyzed_text' in exploit and self.response_field:
                    print(f"\n{Fore.CYAN}Analyzed Field ({self.response_field}):{Style.RESET_ALL}")
                    highlighted_text = self._highlight_indicators(
                        exploit['analyzed_text'],
                        indicators
                    )
                    print(highlighted_text)
                    
                    # Optionally show full response in collapsed form
                    print(f"\n{Fore.CYAN}Full Response (preview):{Style.RESET_ALL}")
                    if len(exploit['full_response']) > 100:
                        print(f"{exploit['full_response'][:100]}... (truncated)")
                    else:
                        print(exploit['full_response'])
                else:
                    # Original behavior for full response
                    highlighted_response = self._highlight_indicators(
                        exploit['full_response'],
                        indicators
                    )
                    print(f"\n{Fore.CYAN}Response:{Style.RESET_ALL}\n{highlighted_response}")
                
                # Display matched indicators
                if 'matched_indicators' in exploit and exploit['matched_indicators']:
                    print(f"\n{Fore.YELLOW}Matched Indicators:{Style.RESET_ALL}")
                    for indicator in exploit['matched_indicators']:
                        print(f"- {indicator}")

        if results.get('blocked_attempts'):
            print(f"\n{Fore.YELLOW}=== Blocked Attempts ==={"="*55}{Style.RESET_ALL}")
            for i, attempt in enumerate(results['blocked_attempts'], 1):
                print(f"\n{Fore.GREEN}Attempt #{i}: {attempt.get('test_name', 'Unnamed Test')}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Prompt:{Style.RESET_ALL}\n{attempt['prompt']}")
                
                # Highlight matched indicators in the response
                if 'matched_indicators' in attempt:
                    indicators = attempt['matched_indicators']
                else:
                    indicators = attempt.get('failure_indicators', [])
                
                # Show the analyzed text if a specific field was extracted
                if 'analyzed_text' in attempt and self.response_field:
                    print(f"\n{Fore.CYAN}Analyzed Field ({self.response_field}):{Style.RESET_ALL}")
                    highlighted_text = self._highlight_indicators(
                        attempt['analyzed_text'],
                        indicators
                    )
                    print(highlighted_text)
                    
                    # Optionally show full response in collapsed form
                    print(f"\n{Fore.CYAN}Full Response (preview):{Style.RESET_ALL}")
                    if len(attempt['full_response']) > 100:
                        print(f"{attempt['full_response'][:100]}... (truncated)")
                    else:
                        print(attempt['full_response'])
                else:
                    # Original behavior for full response
                    highlighted_response = self._highlight_indicators(
                        attempt['full_response'],
                        indicators
                    )
                    print(f"\n{Fore.CYAN}Response:{Style.RESET_ALL}\n{highlighted_response}")
                
                # Display matched indicators
                if 'matched_indicators' in attempt and attempt['matched_indicators']:
                    print(f"\n{Fore.YELLOW}Matched Indicators:{Style.RESET_ALL}")
                    for indicator in attempt['matched_indicators']:
                        print(f"- {indicator}")
                
        print("\n" + "="*80)
    
    def _highlight_indicators(self, response: str, indicators: List[str]) -> str:
        """
        Highlight indicators found in the response
        
        :param response: Response text
        :param indicators: List of indicators to highlight
        :return: Highlighted response text
        """
        highlighted = response
        for indicator in indicators:
            if indicator.lower() in highlighted.lower():
                # Find all case-insensitive matches
                start_idx = 0
                while True:
                    match_idx = highlighted.lower().find(indicator.lower(), start_idx)
                    if match_idx == -1:
                        break
                    # Replace the matched portion with colored version
                    original_text = highlighted[match_idx:match_idx+len(indicator)]
                    highlighted = (
                        highlighted[:match_idx] + 
                        f"{Back.RED}{Fore.WHITE}{original_text}{Style.RESET_ALL}" + 
                        highlighted[match_idx+len(indicator):]
                    )
                    start_idx = match_idx + len(indicator) + len(Back.RED + Fore.WHITE + Style.RESET_ALL)
        return highlighted

    def save_results(self, results: Dict, output_file: str) -> None:
        """
        Save fuzzing results to a JSON file
        
        :param results: Fuzzing results dictionary
        :param output_file: Path to output file
        """
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"Results saved to {output_file}")
        except Exception as e:
            print(f"Error saving results: {e}")

