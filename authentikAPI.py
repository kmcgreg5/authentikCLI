from typing import Optional, Final
from requests import Session

class AuthentikAPI:
    version: Final[str] = "v3"
    def __init__(self, host: str=None, token: str=None):
        self._host: Optional[str] = host
        self.__token: Optional[str] = token
        self._session: Optional[Session] = None
    
    def start_session(self):
        if self._session is None:
            self._session = Session()
    
    def end_session(self):
        if self._session is not None:
            self._session.close()
            self._session = None

    def get_provider_types(self) -> Optional[dict]:
        response = self._session.get(f'{self._host}/api/{self.version}/providers/all/types/', headers={'Authorization':f'Bearer {self.__token}'})
        if response.status_code == 200:
            return response.json()
        return None

    def get_providers(self, search: str=None) -> Optional[dict]:
        params: dict = {}
        if search is not None:
            params["search"] = search
        response = self._session.get(f'{self._host}/api/{self.version}/providers/all/', params=params, headers={'Authorization':f'Bearer {self.__token}'})
        if response.status_code == 200:
            return response.json()
        return None
    
    def get_provider(self, uuid: str, provider_type: str) -> Optional[dict]:
        response = self._session.get(f'{self._host}/api/{self.version}/providers/{provider_type}/{uuid}/', headers={'Authorization':f'Bearer {self.__token}'})
        if response.status_code == 200:
            return response.json()
        return None
    
    def delete_provider(self, uuid: str) -> bool:
        response = self._session.delete(f'{self._host}/api/{self.version}/providers/all/{uuid}/', headers={'Authorization':f'Bearer {self.__token}'})
        if response.status_code == 204:
            return True
        return False
    
    def get_applications(self, search: str=None, full_list: bool=False) -> Optional[dict]:
        params: dict = {"superuser_full_list":full_list}
        if search is not None:
            params["search"] = search
        response = self._session.get(f'{self._host}/api/{self.version}/core/applications/', params=params, headers={'Authorization':f'Bearer {self.__token}'})
        if response.status_code == 200:
            return response.json()
        return None
    
    def get_application(self, slug: str) -> Optional[dict]:
        response = self._session.get(f'{self._host}/api/{self.version}/core/applications/{slug}/', headers={'Authorization':f'Bearer {self.__token}'})
        if response.status_code == 200:
            return response.json()
        return None
    
    def delete_application(self, slug: str) -> bool:
        response = self._session.delete(f'{self._host}/api/{self.version}/core/applications/{slug}/', headers={'Authorization':f'Bearer {self.__token}'})
        if response.status_code == 204:
            return True
        return False

    def get_policies(self) -> Optional[dict]:
        response = self._session.get(f'{self._host}/api/{self.version}/policies/all/', headers={'Authorization':f'Bearer {self.__token}'})
        if response.status_code == 200:
            return response.json()
        return None

    def get_policy_bindings(self, target_uuid: str=None) -> Optional[dict]: 
        params: dict = {}
        if target_uuid is not None:
            params["target"] = target_uuid
        response = self._session.get(f'{self._host}/api/{self.version}/policies/bindings/', params=params, headers={'Authorization':f'Bearer {self.__token}'})
        if response.status_code == 200:
            return response.json()
        return None
    
    def get_property_mapping(self, uuid: str) -> Optional[dict]:
        response = self._session.get(f'{self._host}/api/{self.version}/propertymappings/all/{uuid}/', headers={'Authorization':f'Bearer {self.__token}'})
        if response.status_code == 200:
            return response.json()
        return None
    
    def create_policy_binding(self, params: dict) -> Optional[dict]: # template app uuid 220fa8cc-8519-42fc-8b11-5b3f93f3ba34
        valid_keys = ["policy", "group", "user", "target", "negate", "enabled", "order", "timeout"]
        if validate_keys(valid_keys, params.keys()) is False:
            return None

        response = self._session.post(f'{self._host}/api/{self.version}/policies/bindings/', json=params, headers={'Authorization':f'Bearer {self.__token}'})
        if response.status_code == 201:
            return response.json()
        return None
    
    def create_application(self, params: dict) -> Optional[dict]:
        valid_keys = ["name", "slug", "provider", "open_in_new_tab", "meta_launch_url", "meta_description", "meta_publisher", "policy_engine_mode", "group"]
        if validate_keys(valid_keys, params.keys()) is False:
            return None

        response = self._session.post(f'{self._host}/api/{self.version}/core/applications/', json=params, headers={'Authorization':f'Bearer {self.__token}'})
        if response.status_code == 201:
            return response.json()
        return None
    
    def create_proxy_provider(self, params: dict) -> Optional[dict]:
        valid_keys = ["search", "name", "authorization_flow", "property_mappings", "internal_host", "external_host",  "internal_host_ssl_validation", "certificate", "skip_path_regex", "basic_auth_enabled",
                "basic_auth_password_attribute", "basic_auth_user_attribute", "mode", "intercept_header_auth", "cookie_domain", "jwks_sources", "token_validity"]
        if validate_keys(valid_keys, params.keys()) is False:
            return None

        response = self._session.post(f'{self._host}/api/{self.version}/providers/proxy/', json=params, headers={'Authorization':f'Bearer {self.__token}'})
        if response.status_code == 201:
            return response.json()
        
        return None
    
    def get_outposts(self, search: str=None) -> Optional[dict]:
        params: dict = {}
        if search is not None:
            params["search"] = search
        response = self._session.get(f'{self._host}/api/{self.version}/outposts/instances/', params=params, headers={'Authorization':f'Bearer {self.__token}'})
        if response.status_code == 200:
            return response.json()
        return None

    def update_outpost(self, uuid: str, params: dict) -> Optional[dict]:
        valid_keys = ["name", "type", "providers", "service_connection", "config", "managed"]
        if validate_keys(valid_keys, params.keys()) is False:
            return None

        response = self._session.patch(f'{self._host}/api/{self.version}/outposts/instances/{uuid}/', json=params, headers={'Authorization':f'Bearer {self.__token}'})
        if response.status_code == 200:
            return response.json()
        return None

    def __enter__(self):
        self.start_session()
        return self
    
    def __exit__(self, *args):
        self.end_session()

def validate_keys(valid_keys: list, keys: list) -> bool:
    if len(keys) > len(valid_keys): return False
    for key in keys:
        if key not in valid_keys: return False
    return True