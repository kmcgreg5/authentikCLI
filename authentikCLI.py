from argparse import ArgumentParser
from authentikAPI import AuthentikAPI, validate_keys
from typing import Optional
import sys
import re
import os

def main():
    parser = ArgumentParser(prog="authentikCLI.py")
    subparsers = parser.add_subparsers(help="The supported commands.", dest="command")

    # Add domain parser
    add_domain_parser = subparsers.add_parser("add-domain", help="Create an application and provider, and update the outpost for a new domain.")
    add_domain_parser.add_argument("name", help="The display name of the application and provider.")
    add_domain_parser.add_argument("domain", help="The domain to create.")
    add_domain_parser.add_argument("host", help="The Authentik instance url.")
    add_domain_parser.add_argument("tokenfile", help="The path to a file containing an Authentik authentication token.")

    add_domain_parser.add_argument("--app-template", default="template", help="The template application name to search for.")
    add_domain_parser.add_argument("--app-group", help="The group of the application.")

    add_domain_parser.add_argument("--provider-template", default="template", help="The template provider name to search for.")
    add_domain_parser.add_argument("--provider-mode", default="forward_single", choices=["proxy", "forward_single", "forward_domain"], help="The mode of the provider.")
    add_domain_parser.add_argument("--provider-token-validity", default="hours=24", help="The token validity of the provider.")
    
    add_domain_parser.add_argument("--outpost-name", default="authentik Embedded Outpost", help="The name of the outpost to be updated.")

    # Delete domain parser
    delete_domain_parser = subparsers.add_parser("delete-domain", help="Deletes an application and provider.")
    delete_domain_parser.add_argument("domain", help="The domain to delete.")
    delete_domain_parser.add_argument("host", help="The Authentik instance url.")
    delete_domain_parser.add_argument("tokenfile", help="The path to a file containing an Authentik authentication token.")
    delete_domain_parser.add_argument("--provider-type", default="proxy", choices=["proxy", "ldap", "oauth2", "saml"], help="The provider type to match.")
    
    args = parser.parse_args()

    if args.command == "add-domain":
        token: Optiona[str] = read_token(args.tokenfile)
        if token is None:
            sys.exit("Failed to read token file.")
        provider_args: dict={"provider_template":args.provider_template, "mode":args.provider_mode, "token_validity":args.provider_token_validity}
        application_args: dict={"app_template":args.app_template, "app_group":args.app_group}
        outpost_args: dict={"name":args.outpost_name}
        add_domain(args.name, args.domain, args.host, token, application_args, provider_args, outpost_args)
    elif args.command == "delete-domain":
        token: Optiona[str] = read_token(args.tokenfile)
        if token is None:
            sys.exit("Failed to read token file.")
        delete_domain(args.domain, args.provider_type, args.host, token)
    else:
        parser.print_help()
        sys.exit(1)
    print("Success")
    sys.exit()

def add_domain(name: str, domain: str, host: str, token: str, application_args:dict, provider_args:dict, outpost_args:dict) -> bool:
    provider_keys = ["provider_template", "mode", "token_validity"]
    app_keys = ["app_template", "app_group"]
    outpost_keys = ["name"]
    if validate_keys(app_keys, application_args.keys()) is False:
        sys.exit("Invalid keys passed to application arguments.")
    if validate_keys(provider_keys, provider_args.keys()) is False:
        sys.exit("Invalid keys passed to provider arguments.")
    if validate_keys(outpost_keys, outpost_args.keys()) is False:
        sys.exit("Invalid keys passed to outpost arguments.")
    
    modes = ["proxy", "forward_single", "forward_domain"]
    if provider_args['mode'] not in modes:
        sys.exit("Unimplemented provider mode selected")

    with AuthentikAPI(host, token) as authentik:
        # Check provider is not already registered
        providers: Optional[dict] = authentik.get_applications(full_list=True)
        if providers is None:
            sys.exit("Failed to fetch providers.")
        for provider in providers['results']:
            if name == provider["name"]:
                sys.exit("This name is already registered with a provider.")

        # Fetch app template
        app_template: Optional[dict] = get_app_template(authentik, application_args['app_template'])
        if app_template is None: 
            sys.exit("Failed to fetch application template.")
        
        # Fetch provider template
        provider_template: Optional[dict] = get_provider_template(authentik, provider_args['provider_template'])
        if provider_template is None:
            sys.exit("Failed to fetch provider template.")
        
        # Assemble parameters based on type
        if provider_args["mode"] == "forward_single":
            params: dict = {"name":name, "authorization_flow":provider_template["authorization_flow"], "external_host":f'https://{domain}',
                        "mode":provider_args["mode"], "token_validity":provider_args['token_validity']}
        
        # Create provider
        new_provider: Optiona[dict] = authentik.create_proxy_provider(params)
        if new_provider is None:
            sys.exit("Failed to create proxy provider.")

        params: dict={"name":name, "slug":create_slug(name), "policy_engine_mode":app_template["policy_engine_mode"], "provider":new_provider["pk"]}
        if application_args['app_group'] is not None:
            params["group"] = application_args["app_group"]
        
        # Create application
        new_application: Optional[dict] = authentik.create_application(params)
        if new_application is None:
            authentik.delete_provider(new_provider['pk'])
            sys.exit("Failed to create application.")
        
        # Apply policies
        template_policies: Optional[dict] = authentik.get_policy_bindings(app_template['pk'])
        if template_policies is not None:
            for policy in template_policies['results']:
                params: dict={"target":new_application['pk'], "negate":policy["negate"], "enabled":policy['enabled'], "order":policy['order'], "timeout":policy['timeout']}
                if policy['policy'] is not None:
                    params['policy'] = policy['policy']
                if policy['group'] is not None:
                    params['group'] = policy['group']
                if policy['user'] is not None:
                    params['user'] = policy['user']

                new_policy: Optional[dict]=authentik.create_policy_binding(params)
                if new_policy is None:
                    authentik.delete_application(new_application['slug'])
                    authentik.delete_provider(new_provider['pk'])
                    sys.exit("Failed to bind policy.")
        
        # Add provider to the outpost
        outpost = get_outpost(authentik, outpost_args["name"])
        if outpost is None:
            authentik.delete_application(new_application['slug'])
            authentik.delete_provider(new_provider['pk'])
            sys.exit("Failed to retireve outpost.")
        
        providers: list=outpost["providers"]
        providers.append(new_provider['pk'])
        params: dict={"providers":providers}
        if authentik.update_outpost(outpost['pk'], params) is None:
            authentik.delete_application(new_application['slug'])
            authentik.delete_provider(new_provider['pk'])
            sys.exit("Failed to update outpost.")

def delete_domain(domain: str, prov_type: str, host: str, token: str):
    with AuthentikAPI(host, token) as authentik:
        domain: Optional[dict] = match_domain(authentik, domain, prov_type)
        if domain is None:
            sys.exit("Failed to match domain")
        if authentik.delete_application(domain["assigned_application_slug"]) is False:
            sys.exit("Failed to delete application.")
        if authentik.delete_provider(domain['pk']) is False:
            sys.exit("Failed to delete provider.")

def match_domain(authentik: AuthentikAPI, domain: str, prov_type: str) -> Optional[dict]:
    types: list = ["proxy"] # TODO: Unimplemented type matching: "ldap", "oauth2", "saml"
    if prov_type not in types: return None
    
    providers: Optional[dict] = authentik.get_providers()
    if providers is None: return None
    
    provider = None
    for item in providers['results']:
        detail: Optional[dict] = authentik.get_provider(item['pk'], prov_type)
        if detail is None: continue

        if prov_type == "proxy":
            if domain in detail['external_host'].split("/"):
                provider = detail
                break
    return provider

def get_app_template(authentik: AuthentikAPI, name: str) -> Optional[dict]:
    templates = authentik.get_applications(name, True)
    if templates is None: return None
    for template in templates['results']:
        if template['name'] == name: return template
    return None

def get_provider_template(authentik: AuthentikAPI, name: str) -> Optional[dict]:
    templates = authentik.get_providers(name)
    if templates is None: return None
    for template in templates['results']:
        if template['name'] == name: return template
    return None

def get_outpost(authentik: AuthentikAPI, name: str) -> Optional[dict]:
    outposts: Optional[dict]= authentik.get_outposts(name)
    if outposts is None: return None
    for outpost in outposts['results']:
        if outpost['name'] == name: return outpost
    return None

def create_slug(name: str) -> str:
    slug = name.replace(' ', '-')
    slug = slug.lower()
    slug = re.sub(r'[^-a-zA-Z0-9_]', "", slug)
    return slug

def read_token(token_file: str) -> Optional[str]:
    try:
        if os.path.exists(token_file) and os.path.isfile(token_file):
            with open(token_file, 'r') as file:
                return file.read().strip()
    except Exception:
        return None
    return None

if __name__ == "__main__":
    main()