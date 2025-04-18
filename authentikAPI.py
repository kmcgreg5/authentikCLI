from requests import Session
import typing

class APIException(Exception):
    pass

class AuthentikAPI:
    DEFAULT_PORT: int = 9000
    VERSION: str = "v3"
    def __init__(self, host: str=None, port: int=DEFAULT_PORT, token: str=None):
        self._host = host
        self._port = port
        self.__token = token
        self._session = None
    
    def start_session(self):
        if self._session is None:
            self._session = Session()
    
    def end_session(self):
        if self._session is not None:
            self._session.close()
            self._session = None
    
    def __get_host(self) -> str:
        return f'http://{self._host}:{self._port}'
    
    def __get_url(self, endPoint):
        return f'{self.__get_host()}/api/{self.VERSION}{endPoint}'

    def __validate_response(self, response, additional_codes, *args) -> typing.Any:
        codes: list = [200, 201, 204]

        if additional_codes is not None:
            for code in additional_codes:
                codes.append(code)
        
        if response.status_code not in codes:
            raise APIException(response.text)
        
        json = response.json()    
        #if len(args) == 0:
        #    return
        
        return_value = json
        for arg in args:
            return_value = return_value[arg]
        
        return return_value
    
    def __validate_delete(self, response) -> bool:
        valid_codes: list = [204, 404]

        if response.status_code not in valid_codes:
            raise APIException(response.text)
        
        if response.status_code == 204:
            return True
        
        return False
    
    def __get_token_header(self) -> dict:
        return {'Authorization':f'Bearer {self.__token}'}

    def get_provider_types(self) -> dict:
        endPoint = f'/providers/all/types/'
        response = self._session.get(self.__get_url(endPoint), headers=self.__get_token_header())
        return self.__validate_response(response, None)

    def get_providers(self, search: str=None) -> [dict]:
        params: dict = {}
        if search is not None:
            params["search"] = search

        endPoint = "/providers/all/"
        response = self._session.get(self.__get_url(endPoint), params=params, headers=self.__get_token_header())
        return self.__validate_response(response, None, 'results')
    
    def get_provider(self, uuid: str, provider_type: str) -> dict:
        endPoint = f'/providers/{provider_type}/{uuid}/'
        response = self._session.get(self.__get_url(endPoint), headers=self.__get_token_header())
        return self.__validate_response(response, None)
    
    def delete_provider(self, uuid: str):
        endPoint = f'/providers/all/{uuid}/'
        response = self._session.delete(self.__get_url(endPoint), headers=self.__get_token_header())
        self.__validate_response(response, None)
    
    def get_applications(self, search: str=None, full_list: bool=False) -> dict:
        params: dict = {"superuser_full_list":full_list}
        if search is not None:
            params["search"] = search
        
        endPoint = '/core/applications/'
        response = self._session.get(self.__get_url(endPoint), params=params, headers=self.__get_token_header())
        return self.__validate_response(response, None, 'results')
    
    def get_application(self, slug: str) -> dict:
        endPoint = f'/core/applications/{slug}/'
        response = self._session.get(self.__get_url(endPoint), headers=self.__get_token_header())
        return self.__validate_response(response, None)
    
    def delete_application(self, slug: str) -> bool:
        endPoint = f'/core/applications/{slug}/'
        response = self._session.delete(self.__get_url(endPoint), headers=self.__get_token_header())
        print("RESPONSE:")
        print(response)
        print(response.text)
        return self.__validate_response(response, [404])

    def get_policies(self) -> typing.Optional[dict]:
        endPoint = '/policies/all/'
        response = self._session.get(self.__get_url(endPoint), headers=self.__get_token_header())
        return self.__validate_response(response, None, 'results')

    def get_policy_bindings(self, target_uuid: str=None) -> dict: 
        params: dict = {}
        if target_uuid is not None:
            params["target"] = target_uuid
        
        endPoint = '/policies/bindings/'
        response = self._session.get(self.__get_url(endPoint), params=params, headers=self.__get_token_header())
        return self.__validate_response(response, None, 'results')
    
    def get_property_mapping(self, uuid: str) -> dict:
        endPoint = f'/propertymappings/all/{uuid}/'
        response = self._session.get(self.__get_url(endPoint), headers=self.__get_token_header())
        return self.__validate_response(response, None)
    
    def create_policy_binding(self, params: dict) -> dict: # template app uuid 220fa8cc-8519-42fc-8b11-5b3f93f3ba34
        valid_keys = ["policy", "group", "user", "target", "negate", "enabled", "order", "timeout"]
        if validate_keys(valid_keys, params.keys()) is False:
            raise APIException("Invalid keys passed to policy binding creation.")

        endPoint = '/policies/bindings/'
        response = self._session.post(self.__get_url(endPoint), json=params, headers=self.__get_token_header())
        return self.__validate_response(response, None)
    
    def create_application(self, params: dict) -> dict:
        valid_keys = ["name", "slug", "provider", "open_in_new_tab", "meta_launch_url", "meta_description", "meta_publisher", "policy_engine_mode", "group"]
        if validate_keys(valid_keys, params.keys()) is False:
            raise APIException("Invalid keys passed to application creation.")

        endPoint = "/core/applications/"
        response = self._session.post(self.__get_url(endPoint), json=params, headers=self.__get_token_header())
        return self.__validate_response(response, None)
    
    def create_proxy_provider(self, params: dict) -> dict:
        valid_keys = ["search", "name", "authorization_flow", "property_mappings", "internal_host", "external_host",  "internal_host_ssl_validation", "certificate", "skip_path_regex", "basic_auth_enabled",
                "basic_auth_password_attribute", "basic_auth_user_attribute", "mode", "intercept_header_auth", "cookie_domain", "jwks_sources", "token_validity"]
        if validate_keys(valid_keys, params.keys()) is False:
            raise APIException("Invalid keys passed to provider creation.")

        endPoint = "/providers/proxy/"
        response = self._session.post(self.__get_url(endPoint), json=params, headers=self.__get_token_header())
        return self.__validate_response(response, None)
    
    def get_outposts(self, search: str=None) -> dict:
        params: dict = {}
        if search is not None:
            params["search"] = search
        
        endPoint = '/outposts/instances/'
        response = self._session.get(self.__get_url(endPoint), params=params, headers=self.__get_token_header())
        return self.__validate_response(response, None, 'results')

    def update_outpost(self, uuid: str, params: dict) -> dict:
        valid_keys = ["name", "type", "providers", "service_connection", "config", "managed"]
        if validate_keys(valid_keys, params.keys()) is False:
            raise APIException("Invalid keys passed to outpost update.")

        endPoint = f'/outposts/instances/{uuid}/'
        response = self._session.patch(self.__get_url(endPoint), json=params, headers={'Authorization':f'Bearer {self.__token}'})
        return self.__validate_response(response, None)

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