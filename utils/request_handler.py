# utils/request_handler.py
import requests
import json
import os
from typing import Dict, Any, Optional, Union

class RequestHandler:
    """
    Handles sending requests to LLM endpoints with support for raw HTTP request templates.
    """
    def __init__(self, 
                 headers: Dict[str, str] = None, 
                 timeout: int = 30,
                  proxy: Optional[Union[str, Dict[str, str]]] = None,
                 raw_request_file: Optional[str] = None):
        """
        Initialize request handler with optional headers, timeout, and raw request template.
        
        :param headers: Custom headers for API requests
        :param timeout: Request timeout in seconds
        :param raw_request_file: Path to raw HTTP request template file
        """
        self.headers = headers or {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.timeout = timeout
        self.raw_request_template = self._load_raw_request_template(raw_request_file) if raw_request_file else None
        self.proxies = self._setup_proxies(proxy)

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

    def _load_raw_request_template(self, raw_request_file: str) -> str:
        """
        Load raw HTTP request template from file.
        
        :param raw_request_file: Path to raw request template file
        :return: Raw request template as string
        """
        if not os.path.exists(raw_request_file):
            raise FileNotFoundError(f"Raw request template file not found: {raw_request_file}")
        
        with open(raw_request_file, 'r') as f:
            return f.read()

    def send_request(self, endpoint: str, prompt: str) -> str:
        """
        Send a request to the LLM endpoint.
        
        :param endpoint: API endpoint URL
        :param prompt: Fuzzing payload/prompt
        :return: LLM response
        """
        try:
            # If raw request template is available, use it
            if self.raw_request_template:
                # Replace <PROMPT> placeholder with actual payload
                request_data = self.raw_request_template.replace('<PROMPT>', prompt.replace('"', '\\"'))
                
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
                    
                    ## DEBUG REQUESTS AND RESPONSES 
                    #print(f"=================request================ : \n ")
                    #print("URL:", response.request.url)
                    #print("Method:", response.request.method)
                    #print("Headers:", response.request.headers)
                    #print("Body:", response.request.body)
                    #print(f"=================response================ : \n  {response.text}")
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                
                response.raise_for_status()
                return response.text
            
            # Fallback to default request method
            response = requests.post(
                endpoint, 
                json={'prompt': prompt},
                headers=self.headers,
                proxies=self.proxies,
                timeout=self.timeout
            )
            

            response.raise_for_status()
            return response.text
        
        except requests.RequestException as e:
            return f"Request Error: {str(e)}"