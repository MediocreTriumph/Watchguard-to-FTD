"""
FMC API client with authentication and request handling.
"""

import requests
import time
from typing import Dict, List, Optional, Any
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


class FMCClient:
    """Client for Cisco FMC REST API."""
    
    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = False):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        
        self.base_url = f"https://{self.host}/api/fmc_config/v1"
        self.platform_url = f"https://{self.host}/api/fmc_platform/v1"
        
        self.domain_uuid: Optional[str] = None
        self.auth_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.headers: Dict[str, str] = {}
        
    def authenticate(self) -> bool:
        """Authenticate with FMC and get access token."""
        auth_url = f"{self.platform_url}/auth/generatetoken"
        
        try:
            response = requests.post(
                auth_url,
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code == 204:
                self.auth_token = response.headers.get('X-auth-access-token')
                self.refresh_token = response.headers.get('X-auth-refresh-token')
                self.domain_uuid = response.headers.get('DOMAIN_UUID')
                
                self.headers = {
                    'Content-Type': 'application/json',
                    'X-auth-access-token': self.auth_token
                }
                
                return True
            else:
                print(f"✗ Authentication failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"✗ Authentication error: {e}")
            return False
    
    def refresh_auth_token(self) -> bool:
        """Refresh the authentication token."""
        if not self.refresh_token:
            return self.authenticate()
        
        auth_url = f"{self.platform_url}/auth/refreshtoken"
        
        try:
            response = requests.post(
                auth_url,
                headers={'X-auth-refresh-token': self.refresh_token},
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code == 204:
                self.auth_token = response.headers.get('X-auth-access-token')
                self.refresh_token = response.headers.get('X-auth-refresh-token')
                self.headers['X-auth-access-token'] = self.auth_token
                return True
            else:
                return self.authenticate()
                
        except Exception as e:
            return self.authenticate()
    
    def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        **kwargs
    ) -> requests.Response:
        """Make API request with automatic token refresh."""
        kwargs['verify'] = self.verify_ssl
        kwargs['timeout'] = kwargs.get('timeout', 30)
        kwargs['headers'] = self.headers
        
        response = requests.request(method, endpoint, **kwargs)
        
        # Token expired - refresh and retry once
        if response.status_code == 401:
            if self.refresh_auth_token():
                kwargs['headers'] = self.headers
                response = requests.request(method, endpoint, **kwargs)
        
        return response
    
    def get_paginated(
        self, 
        endpoint: str, 
        params: Optional[Dict] = None,
        limit: int = 1000
    ) -> List[Dict]:
        """Get all items from a paginated endpoint."""
        all_items = []
        offset = 0
        
        if params is None:
            params = {}
        
        while True:
            params['offset'] = offset
            params['limit'] = limit
            params['expanded'] = True
            
            response = self._make_request('GET', endpoint, params=params)
            
            if response.status_code != 200:
                break
            
            data = response.json()
            items = data.get('items', [])
            
            if not items:
                break
            
            all_items.extend(items)
            
            # Check if more pages exist
            paging = data.get('paging', {})
            if offset + len(items) >= paging.get('count', 0):
                break
            
            offset += limit
            time.sleep(0.1)  # Rate limiting
        
        return all_items
    
    def get_objects(self, object_type: str) -> List[Dict]:
        """Get all objects of a specific type."""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/{object_type}"
        return self.get_paginated(endpoint)
    
    def create_object(self, object_type: str, data: Dict) -> Dict:
        """Create an object in FMC."""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/object/{object_type}"
        
        response = self._make_request('POST', endpoint, json=data)
        
        if response.status_code == 201:
            return response.json()
        else:
            return {
                'error': response.text,
                'status_code': response.status_code
            }
    
    def create_access_policy(self, name: str, default_action: str = "BLOCK") -> Dict:
        """Create a new Access Control Policy."""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/policy/accesspolicies"
        
        data = {
            "type": "AccessPolicy",
            "name": name,
            "defaultAction": {
                "action": default_action,
                "logBegin": False,
                "logEnd": False,
                "sendEventsToFMC": False
            }
        }
        
        response = self._make_request('POST', endpoint, json=data)
        
        if response.status_code == 201:
            return response.json()
        else:
            return {
                'error': response.text,
                'status_code': response.status_code
            }
    
    def create_access_rule(self, policy_id: str, rule_data: Dict) -> Dict:
        """Create an access control rule in a policy."""
        endpoint = f"{self.base_url}/domain/{self.domain_uuid}/policy/accesspolicies/{policy_id}/accessrules"
        
        response = self._make_request('POST', endpoint, json=rule_data)
        
        if response.status_code == 201:
            return response.json()
        else:
            return {
                'error': response.text,
                'status_code': response.status_code
            }
