import requests
import json
import os
import logging
from typing import Dict, Any, Optional, Union

# Set up logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('RequestHandler')


from utils.bypass_techniques.DAN import DAN
from utils.bypass_techniques.relative import relative
from utils.bypass_techniques.history import history
from utils.bypass_techniques.encoding_prompt import encoding_prompt
from utils.bypass_techniques.ignore_instructions import ignore_instructions
from utils.encoders.encoders import *

# Dictionary mapping of available bypass techniques
BYPASS_TECHNIQUES = {
    'DAN': DAN,
    'relative': relative,
    'encoding_prompt': encoding_prompt,
    'history': history,
    'ignore_instructions': ignore_instructions
}

# Dictionary mapping of available prompt encoders
PROMPT_ENCODERS = {
    'piped_string': piped_string,
    'base32': base32_prompt,
    'base64': base64_prompt,
    'binary': binary_prompt,
    'double_base64': double_base64_prompt,
    'hex': hex_prompt,
    'leet': leet_prompt,
    'rot13': rot13_prompt,
    'unicode': unicode_prompt
}


class RequestHandler:
    """
    Handles sending requests to LLM endpoints with support for raw HTTP request templates.
    """
    
    def __init__(self, 
                headers: Dict[str, str] = None, 
                timeout: int = 30,
                proxy: Optional[Union[str, Dict[str, str]]] = None,
                raw_request_file: Optional[str] = None,
                encoder: Optional[str] = None,
                bypass_technique: Optional[str] = None
                ):
        """
        Initialize request handler with optional headers, timeout, and raw request template.
        
        :param headers: Custom headers for API requests
        :param timeout: Request timeout in seconds
        :param proxy: Proxy configuration as string or dictionary
        :param raw_request_file: Path to raw HTTP request template file
        :param encoder: Name of encoder function to use
        :param bypass_technique: Name of bypass technique to use
        """
        self.headers = headers or {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.timeout = timeout
        self.raw_request_template = self._load_raw_request_template(raw_request_file) if raw_request_file else None
        self.proxies = self._setup_proxies(proxy)
        
        # Store encoder and bypass technique names
        self.encoder_name = encoder
        self.bypass_technique_name = bypass_technique
        
        # Set default bypass technique if encoder is specified but bypass is not
        if encoder and not bypass_technique:
            self.bypass_technique_name = "encoding_prompt"
            logger.info(f"Encoder specified without bypass technique. Setting default bypass technique to 'encoding_prompt'")
        
        # Initialize encoder function
        self.encoder_function = None
        if encoder:
            if encoder in PROMPT_ENCODERS:
                self.encoder_function = PROMPT_ENCODERS[encoder]
                logger.info(f"Using encoder: {encoder}")
            else:
                logger.warning(f"Encoder '{encoder}' not found in available encoders")
        
        # Initialize bypass technique function
        self.bypass_technique_function = None
        if self.bypass_technique_name:
            if self.bypass_technique_name in BYPASS_TECHNIQUES:
                self.bypass_technique_function = BYPASS_TECHNIQUES[self.bypass_technique_name]
                logger.info(f"Using bypass technique: {self.bypass_technique_name}")
            else:
                logger.warning(f"Bypass technique '{self.bypass_technique_name}' not found in available techniques")
        
        logger.info(f"RequestHandler initialized: encoder={encoder}, bypass={self.bypass_technique_name}")

    def _setup_proxies(self, proxy: Optional[Union[str, Dict[str, str]]]) -> Optional[Dict[str, str]]:
        """
        Set up proxy configuration.
        
        :param proxy: Proxy configuration as string or dict
        :return: Proxy configuration dict compatible with requests
        """
        if not proxy:
            return None
            
        if isinstance(proxy, str):
            # Convert string proxy to dict format
            return {
                'http': proxy,
                'https': proxy
            }
        return proxy

    def _load_raw_request_template(self, raw_request_file: str) -> Optional[str]:
        """
        Load raw HTTP request template from file.
        
        :param raw_request_file: Path to raw request template file
        :return: Raw request template as string or None if file not found
        """
        if not raw_request_file:
            return None
            
        if not os.path.exists(raw_request_file):
            logger.error(f"Raw request template file not found: {raw_request_file}")
            raise FileNotFoundError(f"Raw request template file not found: {raw_request_file}")
        
        with open(raw_request_file, 'r') as f:
            template = f.read()
            logger.debug(f"Loaded raw request template from {raw_request_file}")
            return template
            
    def _send_raw_request(self, endpoint: str, prompt: str) -> str:
        """
        Send request using raw HTTP template.
        
        :param endpoint: API endpoint URL
        :param prompt: Prompt to send
        :return: Response text
        """
        logger.debug(f"Sending raw request to {endpoint}")
        
        # Replace <PROMPT> placeholder with actual payload
        escaped_prompt = prompt.replace('"', '\\"')
        request_data = self.raw_request_template.replace('<PROMPT>', escaped_prompt)
        
        # Determine request method and headers
        request_lines = request_data.split('\n')
        method_line = request_lines[0]
        method = method_line.split()[0]
        
        # Extract headers
        headers = {}
        body_start = 0
        for i, line in enumerate(request_lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # Extract body
        body = '\n'.join(request_lines[body_start:]).strip()
        
        logger.debug(f"Raw request method: {method}")
        logger.debug(f"Raw request headers: {headers}")
        
        # Make request based on method
        if method == 'GET':
            response = requests.get(
                endpoint, 
                headers=headers, 
                params=json.loads(body) if body else None,
                proxies=self.proxies,
                timeout=self.timeout
            )
        elif method == 'POST':
            response = requests.post(
                endpoint, 
                headers=headers, 
                data=body,
                proxies=self.proxies,
                timeout=self.timeout
            )
        else:
            logger.error(f"Unsupported HTTP method: {method}")
            raise ValueError(f"Unsupported HTTP method: {method}")
        
        response.raise_for_status()
        logger.debug(f"Raw request successful, status code: {response.status_code}")
        return response.text

    def _send_standard_request(self, endpoint: str, prompt: str) -> str:
        """
        Send standard JSON request.
        
        :param endpoint: API endpoint URL
        :param prompt: Prompt to send
        :return: Response text
        """
        logger.debug(f"Sending standard request to {endpoint}")
        
        response = requests.post(
            endpoint, 
            json={'prompt': prompt},
            headers=self.headers,
            proxies=self.proxies,
            timeout=self.timeout
        )
        response.raise_for_status()
        logger.debug(f"Standard request successful, status code: {response.status_code}")
        return response.text

    def send_request(self, endpoint: str, prompt: str) -> str:
        """
        Send a request to the LLM endpoint.
        
        :param endpoint: API endpoint URL
        :param prompt: Fuzzing payload/prompt
        :return: LLM response
        """
        try:
            # Log current state before sending request
            logger.info(f"Preparing to send request with encoder={self.encoder_name}, bypass={self.bypass_technique_name}")
            logger.debug(f"Encoder function: {self.encoder_function}")
            logger.debug(f"Bypass function: {self.bypass_technique_function}")
            
            original_prompt = prompt
            
            # Apply encoder if specified
            if self.encoder_function:
                logger.info(f"Applying encoder: {self.encoder_name}")
                prompt = self.encoder_function(prompt)
                logger.debug(f"Encoded prompt: {prompt[:50]}...")
            
            # Apply bypass technique if specified
            if self.bypass_technique_function:
                logger.info(f"Applying bypass technique: {self.bypass_technique_name}")
                if self.bypass_technique_name == "encoding_prompt":
                    prompts = self.bypass_technique_function(self.encoder_name,prompt)
                else:
                    prompts = self.bypass_technique_function(prompt)
                logger.info(f"Generated {len(prompts)} prompts using bypass technique")
                if isinstance(prompts, str):  # Check if it's a single string
                    try:
                        if self.raw_request_template:
                            return self._send_raw_request(endpoint, prompts), prompts
                        else:
                            return self._send_standard_request(endpoint, prompts), prompts
                    except requests.RequestException as e:
                        # Handle exception properly - either re-raise or return an error value
                        raise e  # Or return None, or handle however you want
                        
                elif isinstance(prompts, list):  # If prompts is a list
                    results = []
                    for prompt in prompts:
                        try:
                            if self.raw_request_template:
                                result = self._send_raw_request(endpoint, prompt)
                            else:
                                result = self._send_standard_request(endpoint, prompt)
                            results.append((result, prompt))
                        except requests.RequestException as e:
                            # Continue with the next prompt on failure
                            continue
                    return results
                            
                
                # If all prompts failed, return error
                logger.error("All bypass technique prompts failed")
                return "Error: All bypass technique prompts failed"
            else:
                # No bypass technique, send single request
                logger.info("Sending single request (no bypass technique)")
                if self.raw_request_template:
                    return self._send_raw_request(endpoint, prompt), prompt
                else:
                    return self._send_standard_request(endpoint, prompt), prompt
                    
        except requests.RequestException as e:
            logger.error(f"Request error: {e}")
            return f"Request Error: {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return f"Unexpected Error: {str(e)}"

    def __str__(self):
        """String representation for debugging purposes"""
        return (f"RequestHandler(encoder={self.encoder_name}, "
                f"bypass={self.bypass_technique_name}, "
                f"has_template={self.raw_request_template is not None})")