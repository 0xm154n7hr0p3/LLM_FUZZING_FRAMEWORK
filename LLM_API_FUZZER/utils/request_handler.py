# utils/request_handler.py
import requests
import json
import os
import logging
import time
from typing import Dict, Any, Optional, Union, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RequestError(Exception):
    """Custom exception for request handler errors with status code and details."""
    def __init__(self, message: str, status_code: Optional[int] = None, details: Optional[Dict] = None):
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)

class RequestHandler:
    """
    Handles sending requests to LLM endpoints with support for raw HTTP request templates.
    """
    def __init__(self, 
                 headers: Dict[str, str] = None, 
                 timeout: int = 30,
                 raw_request_file: Optional[str] = None,
                 max_retries: int = 3,
                 retry_delay: int = 2):
        """
        Initialize request handler with optional headers, timeout, and raw request template.
        
        :param headers: Custom headers for API requests
        :param timeout: Request timeout in seconds
        :param raw_request_file: Path to raw HTTP request template file
        :param max_retries: Maximum number of retry attempts for transient errors
        :param retry_delay: Delay between retries in seconds
        """
        self.headers = headers or {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.raw_request_template = None
        
        if raw_request_file:
            try:
                self.raw_request_template = self._load_raw_request_template(raw_request_file)
            except FileNotFoundError as e:
                logger.error(f"Failed to load raw request template: {str(e)}")
                raise

    def _load_raw_request_template(self, raw_request_file: str) -> str:
        """
        Load raw HTTP request template from file.
        
        :param raw_request_file: Path to raw request template file
        :return: Raw request template as string
        :raises FileNotFoundError: If the template file doesn't exist
        """
        if not os.path.exists(raw_request_file):
            raise FileNotFoundError(f"Raw request template file not found: {raw_request_file}")
        
        try:
            with open(raw_request_file, 'r') as f:
                return f.read()
        except (IOError, OSError) as e:
            logger.error(f"Error reading raw request template file: {str(e)}")
            raise

    def _parse_raw_request(self, raw_request: str, prompt: str) -> Tuple[str, Dict[str, str], Any]:
        """
        Parse raw HTTP request template and substitute prompt.
        
        :param raw_request: Raw HTTP request template
        :param prompt: Prompt to substitute
        :return: Tuple of (method, headers, body)
        :raises ValueError: If template format is invalid
        """
        try:
            # Replace <PROMPT> placeholder with actual payload
            request_data = raw_request.replace('<PROMPT>', prompt.replace('"', '\\"'))
            
            # Split into lines and validate
            request_lines = request_data.split('\n')
            if not request_lines:
                raise ValueError("Empty request template")
                
            # Parse method line
            method_line = request_lines[0]
            method_parts = method_line.split()
            if len(method_parts) < 2:
                raise ValueError(f"Invalid request method line: {method_line}")
            method = method_parts[0]
            
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
            
            return method, headers, body
        except Exception as e:
            logger.error(f"Error parsing raw request template: {str(e)}")
            raise ValueError(f"Failed to parse raw request template: {str(e)}")

    def send_request(self, endpoint: str, prompt: str) -> Union[str, Dict[str, Any]]:
        """
        Send a request to the LLM endpoint with retries for transient errors.
        
        :param endpoint: API endpoint URL
        :param prompt: Fuzzing payload/prompt
        :return: LLM response as string or parsed JSON
        :raises RequestError: If request fails after retries
        """
        retry_count = 0
        last_exception = None
        
        while retry_count <= self.max_retries:
            try:
                if retry_count > 0:
                    logger.info(f"Retry attempt {retry_count}/{self.max_retries}")
                    time.sleep(self.retry_delay)
                
                # Use raw request template if available
                if self.raw_request_template:
                    method, headers, body = self._parse_raw_request(self.raw_request_template, prompt)
                    
                    response = self._execute_request(endpoint, method, headers, body)
                else:
                    # Fallback to default request method
                    response = requests.post(
                        endpoint, 
                        json={'prompt': prompt},
                        headers=self.headers,
                        timeout=self.timeout
                    )
                
                # Check for HTTP errors
                response.raise_for_status()
                
                # Try to parse JSON response, fallback to text if not valid JSON
                try:
                    return response.json()
                except json.JSONDecodeError:
                    return response.text
                
            except requests.exceptions.Timeout as e:
                logger.warning(f"Request timeout: {str(e)}")
                last_exception = RequestError(f"Request timed out after {self.timeout}s", details={"original_error": str(e)})
                retry_count += 1
                
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Connection error: {str(e)}")
                last_exception = RequestError(f"Connection error", details={"original_error": str(e)})
                retry_count += 1
                
            except requests.exceptions.HTTPError as e:
                status_code = e.response.status_code
                logger.error(f"HTTP error {status_code}: {str(e)}")
                
                # Don't retry client errors (4xx) except 429 (Too Many Requests)
                if 400 <= status_code < 500 and status_code != 429:
                    raise RequestError(
                        f"HTTP error {status_code}", 
                        status_code=status_code,
                        details={
                            "response_text": e.response.text,
                            "original_error": str(e)
                        }
                    )
                
                last_exception = RequestError(
                    f"HTTP error {status_code}", 
                    status_code=status_code,
                    details={
                        "response_text": e.response.text,
                        "original_error": str(e)
                    }
                )
                retry_count += 1
                
            except requests.RequestException as e:
                logger.error(f"Request error: {str(e)}")
                last_exception = RequestError(f"Request error", details={"original_error": str(e)})
                retry_count += 1
                
            except ValueError as e:
                # Don't retry template parsing errors
                logger.error(f"Value error: {str(e)}")
                raise RequestError(f"Invalid request configuration: {str(e)}")
                
            except Exception as e:
                logger.error(f"Unexpected error: {str(e)}")
                last_exception = RequestError(f"Unexpected error", details={"original_error": str(e)})
                retry_count += 1
        
        # All retries failed
        logger.error(f"All {self.max_retries} retry attempts failed")
        if last_exception:
            raise last_exception
        else:
            raise RequestError("Request failed after all retry attempts")

    def _execute_request(self, endpoint: str, method: str, headers: Dict[str, str], body: str) -> requests.Response:
        """
        Execute HTTP request based on method.
        
        :param endpoint: API endpoint URL
        :param method: HTTP method (GET, POST, etc.)
        :param headers: Request headers
        :param body: Request body
        :return: Response object
        :raises ValueError: If method is not supported
        """
        logger.debug(f"Executing {method} request to {endpoint}")
        
        if method == 'GET':
            return requests.get(
                endpoint, 
                headers=headers, 
                params=json.loads(body) if body else None,
                timeout=self.timeout
            )
        elif method == 'POST':
            return requests.post(
                endpoint, 
                headers=headers, 
                data=body,
                timeout=self.timeout
            )
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")