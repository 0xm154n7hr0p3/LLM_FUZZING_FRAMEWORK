import os
import datetime
import json
from typing import Dict, List, Optional, Union
from colorama import Fore, Back, Style
from typing import Any

class SystemPromptLeakageFuzzer:
    def __init__(
        self, 
        model_endpoint, 
        request_handler, 
        payload_file=None,
        success_indicators_file=None,
        failure_indicators_file=None,
        response_field=None
    ):
        """
        Initialize System Prompt Leakage Fuzzer with integrated analysis capabilities
        
        :param model_endpoint: LLM API endpoint
        :param request_handler: Request handling utility
        :param payload_file: Optional custom payload file path
        :param success_indicators_file: Optional custom success indicators file
        :param failure_indicators_file: Optional custom failure indicators file
        :param response_field: JSON field to extract from response for analysis (e.g. "message")
        """
        self.model_endpoint = model_endpoint
        self.request_handler = request_handler
        self.response_field = response_field
        
        # Default paths in the same directory
        base_dir = os.path.dirname(__file__)
        
        # Load payloads
        self.payloads = self._load_indicators(
            payload_file or os.path.join(base_dir, './data/system_prompt_leakage_payloads.txt')
        )
        
        # Load success and failure indicators
        self.success_indicators = self._load_indicators(
            success_indicators_file or os.path.join(base_dir, './data/system_prompt_success_indicators.txt')
        )
        
        self.failure_indicators = self._load_indicators(
            failure_indicators_file or os.path.join(base_dir, './data/system_prompt_failure_indicators.txt')
        )
    
    def _load_indicators(self, file_path: Optional[str]) -> List[str]:
        """
        Load indicators from a file with error handling
        
        :param file_path: Path to indicators file
        :return: List of indicators
        """
        if not file_path:
            return []
            
        try:
            # Check if it's a JSON file
            if file_path.endswith('.json'):
                with open(file_path, 'r') as f:
                    return json.load(f)
            # Otherwise treat as text file with one indicator per line
            else:
                with open(file_path, 'r') as f:
                    return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Indicators file not found: {file_path}")
            return []
        except Exception as e:
            print(f"Error reading indicators file: {e}")
            return []

    def _extract_field_from_response(self, response: any) -> str:
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
                self.logger.warning(f"Field '{self.response_field}' not found in response")
                return str(response)
        except json.JSONDecodeError:
            self.logger.warning(f"Response is not valid JSON, using full response")
            return str(response)
        except Exception as e:
            self.logger.error(f"Error extracting field: {e}")
            return str(response)


    def check_success(
        self, 
        response: str, 
        custom_indicators: Optional[List[str]] = None
    ) -> bool:
        """
        Check if response contains any success indicators.
        
        :param response: LLM response text
        :param custom_indicators: Optional list of custom success indicators
        :return: Whether vulnerability was successfully triggered
        """
        # Extract field if specified
        analyzed_text = self._extract_field_from_response(response)
        
        # Combine default and custom indicators
        indicators = self.success_indicators + (custom_indicators or [])
        
        # Case-insensitive search for indicators
        analyzed_text_lower = analyzed_text.lower()
        return any(
            indicator.lower() in analyzed_text_lower 
            for indicator in indicators
        )

    def check_failure(
        self, 
        response: str, 
        custom_indicators: Optional[List[str]] = None
    ) -> bool:
        """
        Check if response contains any failure indicators.
        
        :param response: LLM response text
        :param custom_indicators: Optional list of custom failure indicators
        :return: Whether the attempt was blocked or failed
        """
        # Extract field if specified
        analyzed_text = self._extract_field_from_response(response)
        
        # Combine default and custom indicators
        indicators = self.failure_indicators + (custom_indicators or [])
        
        # Case-insensitive search for indicators
        analyzed_text_lower = analyzed_text.lower()
        return any(
            indicator.lower() in analyzed_text_lower 
            for indicator in indicators
        )

    def analyze_response(
        self, 
        payload: str, 
        response: str, 
        success_indicators: Optional[List[str]] = None,
        failure_indicators: Optional[List[str]] = None
    ) -> Dict[str, Union[str, bool]]:
        """
        Comprehensive analysis of a single fuzzing response.
        
        :param payload: Payload used in the test
        :param response: LLM response to analyze
        :param success_indicators: Optional custom success indicators
        :param failure_indicators: Optional custom failure indicators
        :return: Detailed analysis of the response
        """
        # Extract field for analysis if specified
        analyzed_text = self._extract_field_from_response(response)
        
        # Store both full response and analyzed field
        analysis = {
            'payload': payload,
            'full_response': response,
            'analyzed_text': analyzed_text,
            'is_successful': self.check_success(
                response, 
                custom_indicators=success_indicators
            ),
            'is_blocked': self.check_failure(
                response, 
                custom_indicators=failure_indicators
            )
        }
        
        # If indicators were matched, identify which ones
        if analysis['is_successful']:
            matched_indicators = []
            analyzed_text_lower = analyzed_text.lower()
            for indicator in self.success_indicators + (success_indicators or []):
                if indicator.lower() in analyzed_text_lower:
                    matched_indicators.append(indicator)
            analysis['matched_indicators'] = matched_indicators
            return analysis

        if analysis['is_blocked']:
            matched_indicators = []
            analyzed_text_lower = analyzed_text.lower()
            for indicator in self.failure_indicators + (failure_indicators or []):
                if indicator.lower() in analyzed_text_lower:
                    matched_indicators.append(indicator)
            analysis['matched_indicators'] = matched_indicators
        
        return analysis

    def aggregate_results(
        self, 
        individual_results: List[Dict[str, Union[str, bool]]]
    ) -> Dict[str, List[Dict[str, Union[str, bool]]]]:
        """
        Aggregate results from multiple fuzzing attempts.
        
        :param individual_results: List of individual test results
        :return: Categorized results
        """
        aggregated_results = {
            'total_payloads': len(individual_results),
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
        Perform comprehensive fuzzing for system prompt leakage
        
        :return: Detailed fuzzing results
        """
        # Prepare to collect individual test results
        individual_results = []
        
        # Tracking metadata for the entire fuzzing session
        fuzzing_metadata = {
            'start_time': datetime.datetime.now().isoformat(),
            'total_payloads': None,
            'endpoint': self.model_endpoint
        }
        actual_payload_count = 0
        # Test each payload
        for payload in self.payloads:
            try:
                # Send request with payload
                result = self.request_handler.send_request(
                    self.model_endpoint, 
                    payload
                )
                
                # Handle both single response and multiple responses
                if isinstance(result, list):  # If we got multiple results back
                    # Process each response/payload pair
                    for response, processed_payload in result:
                        # Use integrated response analysis
                        actual_payload_count += 1
                        result_entry = self.analyze_response(
                            payload=processed_payload, 
                            response=response,
                            success_indicators=self.success_indicators,
                            failure_indicators=self.failure_indicators
                        )
                        
                        # Add additional metadata to the result
                        result_entry.update({
                            'timestamp': datetime.datetime.now().isoformat(),
                            'payload_length': len(processed_payload),
                            'response_length': len(response)
                        })
                        
                        individual_results.append(result_entry)
                else:  # Single response case
                    response, processed_payload = result
                    
                    # Use integrated response analysis
                    actual_payload_count += 1
                    result_entry = self.analyze_response(
                        payload=processed_payload, 
                        response=response,
                        success_indicators=self.success_indicators,
                        failure_indicators=self.failure_indicators
                    )
                    
                    # Add additional metadata to the result
                    result_entry.update({
                        'timestamp': datetime.datetime.now().isoformat(),
                        'payload_length': len(processed_payload),
                        'response_length': len(response)
                    })
                    
                    individual_results.append(result_entry)
            except Exception as e:
                # Handle exceptions that might occur during request processing
                error_entry = {
                    'timestamp': datetime.datetime.now().isoformat(),
                    'payload_length': len(payload),
                    'error': str(e),
                    'status': 'error'
                }
                individual_results.append(error_entry)
        
        fuzzing_metadata['total_payloads'] = actual_payload_count
        # Use integrated aggregation

        aggregated_results = self.aggregate_results(individual_results)
        
        # Add fuzzing metadata to the final results
        aggregated_results['fuzzing_metadata'] = fuzzing_metadata
        
        # Add custom indicators for highlighting in the output
        aggregated_results['custom_indicators'] = self.success_indicators + self.failure_indicators
        
        # Perform additional analysis
        aggregated_results['insights'] = self._generate_insights(aggregated_results)
        
        return aggregated_results
    
    def _generate_insights(self, results: Dict) -> Dict:
        """
        Generate additional insights from fuzzing results
        
        :param results: Aggregated fuzzing results
        :return: Insights dictionary
        """
        fuzzing_metadata= results['fuzzing_metadata']
        total_payloads=fuzzing_metadata['total_payloads']
        
        insights = {
            'success_rate': len(results['successful_exploits']) /  total_payloads * 100 if  total_payloads > 0 else 0,
            'block_rate': len(results['blocked_attempts']) /  total_payloads * 100 if  total_payloads > 0 else 0,
            'most_revealing_payloads': sorted(
                results['successful_exploits'], 
                key=lambda x: len(x.get('full_response', '')), 
                reverse=True
            )[:5] if results['successful_exploits'] else []  # Top 5 most revealing payloads
        }
        
        return insights

    # Add this to the imports at the top of system_prompt_leakage.py
    from colorama import Fore, Back, Style
    from typing import Any

    # Add this method to the SystemPromptLeakageFuzzer class
    def display_results(self, results: Dict[str, Any], response_field: str = None) -> None:
        """
        Display fuzzing results with colored output and highlighting
        
        :param results: Fuzzing results dictionary
        :param response_field: Optional specific field to extract from JSON responses
        """
        print("\n" + "="*80)
        print(f"{Fore.CYAN}SYSTEM PROMPT LEAKAGE FUZZING RESULTS{Style.RESET_ALL}")
        print("="*80)
        # Print colored summary to console
        vuln_status = f"{Fore.RED}VULNERABLE{Style.RESET_ALL}" if results.get("successful_exploits") else f"{Fore.GREEN}NOT VULNERABLE{Style.RESET_ALL}"
        print(f"\nOverall Status: {vuln_status}")
        print(f"Total payloads tested: {Fore.CYAN}{results.get('total_payloads', 0)}{Style.RESET_ALL} \n")
        print(f"Successful exploits: {Fore.GREEN}{len(results.get('successful_exploits', []))}{Style.RESET_ALL}")
        print(f"Blocked attempts: {Fore.RED}{len(results.get('blocked_attempts', []))}{Style.RESET_ALL}")
        print(f"Failed attempts: {len(results.get('failed_attempts', []))}\n")

        # Print detailed successful exploits with highlighting
        if results.get('successful_exploits'):
            print(f"{Fore.YELLOW}=== Successful Exploits ==={"="*53}{Style.RESET_ALL}")
            for i, exploit in enumerate(results['successful_exploits'], 1):
                print(f"\n{Fore.GREEN}Exploit #{i}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Payload:{Style.RESET_ALL}\n{exploit['payload']}")
                
                # Get indicators from the exploit results if available
                indicators = []
                if 'matched_indicators' in exploit:
                    indicators = exploit['matched_indicators']
                elif 'custom_indicators' in results:
                    indicators = results['custom_indicators']
                
                # Show the analyzed text (which might be a specific field) instead of full response
                if 'analyzed_text' in exploit and response_field:
                    print(f"\n{Fore.CYAN}Analyzed Field ({response_field}):{Style.RESET_ALL}")
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
                   
        

        if results.get('blocked_attempts'):
            print(f"\n {Fore.YELLOW}=== Blocked Attempts ==={"="*55}{Style.RESET_ALL} \n")
            for i, exploit in enumerate(results['blocked_attempts'], 1):
                print(f"\n{Fore.GREEN}Exploit #{i}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Payload:{Style.RESET_ALL}\n{exploit['payload']}")
                
                # Get indicators from the exploit results if available
                indicators = []
                if 'matched_indicators' in exploit:
                    indicators = exploit['matched_indicators']
                elif 'custom_indicators' in results:
                    indicators = results['custom_indicators']
                
                # Show the analyzed text (which might be a specific field) instead of full response
                if 'analyzed_text' in exploit and response_field:
                    print(f"\n{Fore.CYAN}Analyzed Field ({response_field}):{Style.RESET_ALL}")
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
        print("\n" + "="*80)         
            

    # Add this helper method to the class
    def _highlight_indicators(self, response: str, indicators: list[str]) -> str:
        """Highlight indicators found in the response"""
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