from argparse import ArgumentParser, Namespace
from authentikAPI import AuthentikAPI, validate_keys
from typing import Optional
import sys
import re
import os

class CLIException(Exception):
    pass

def main(args: list=sys.argv[1:]):
    parsed_args: Optional[Namespace] = None
    try:
        parsed_args = __parse_args(args)
        if parsed_args.item == 'domain':
            if parsed_args.operation == 'add':
                __validate_options(parsed_args)
                __add_domain(parsed_args)
            elif parsed_args.operation == 'remove':
                __validate_options(parsed_args)
                __remove_domain(parsed_args)
            else:
                domain_parser.print_help()
                sys.exit(1)
        else:
            parser.print_help()
            sys.exit(1)

    except Exception as e:
        print(f'Exception occurred: {str(e)}')
        if (parsed_args is not None and parsed_args.debug):
            raise e

        sys.exit(1)

    print("Success")

'''
    CLI HELPER METHODS
'''
def __parse_args(args):
    parser = ArgumentParser(prog="Authentik CLI")
    parser.add_argument("--host", help="The Authentik Server host.", nargs='?')
    parser.add_argument("--token", help="The token to use for authentication.", nargs='?')
    parser.add_argument("--port", help="The port to connect to.", nargs='?', type=int, default=AuthentikAPI.DEFAULT_PORT)
    parser.add_argument("--debug", help="Whether to enable debug or not", action='store_true')

    items = parser.add_subparsers(help="The supported items to operate on.", dest="item")

    # Domain parser
    domain_parser = items.add_parser("domain")
    operations = domain_parser.add_subparsers(help="The operation to perform.", dest="operation")
    # Add Domain parser
    domain_add_parser = operations.add_parser("add")
    domain_add_parser.add_argument("name", help="The display name of the application and provider.")
    domain_add_parser.add_argument("domain", help="The domain to create.")
    domain_add_parser.add_argument("--app-template", default="template", nargs="?", help="The template application name to search for.")
    domain_add_parser.add_argument("--app-group", help="The group of the application.", nargs="?")
    domain_add_parser.add_argument("--provider-template", default="template", help="The template provider name to search for.", nargs="?")
    domain_add_parser.add_argument("--provider-mode", default="forward_single", choices=["proxy", "forward_single", "forward_domain"], help="The mode of the provider.")
    domain_add_parser.add_argument("--provider-token-validity", default="hours=24", help="The token validity of the provider.", nargs="?")
    domain_add_parser.add_argument("--outpost-name", default="authentik Embedded Outpost", help="The name of the outpost to be updated.", nargs="?")
    # Delete domain parser
    delete_domain_parser = operations.add_parser("remove")
    delete_domain_parser.add_argument("domain", help="The domain to remove.")
    delete_domain_parser.add_argument("--provider-type", default="proxy", choices=["proxy", "ldap", "oauth2", "saml"], help="The provider type to match.")
    
    return parser.parse_args(args)

def __validate_options(args):
    def throwRequiredOptionException(option: str):
        parsed_option = option
        while parsed_option.startswith('-'):
            parsed_option = parsed_option[1:]

        value = getattr(args, parsed_option)
        if value is None:
            raise CLIException(f'The option \'{option}\' is undefined.')

    throwRequiredOptionException("--host")
    throwRequiredOptionException("--token")
    throwRequiredOptionException("--port")

'''
    COMMANDS
'''

def __add_domain(args):
    provider_args: dict={"provider_template":args.provider_template, "mode":args.provider_mode, "token_validity":args.provider_token_validity}
    application_args: dict={"app_template":args.app_template, "app_group":args.app_group}
    outpost_args: dict={"name":args.outpost_name}

    provider_keys = ["provider_template", "mode", "token_validity"]
    app_keys = ["app_template", "app_group"]
    outpost_keys = ["name"]
    if validate_keys(app_keys, application_args.keys()) is False:
        raise CLIException('Invalid keys passed to application arguments')
    if validate_keys(provider_keys, provider_args.keys()) is False:
        raise CLIException("Invalid keys passed to provider arguments.")
    if validate_keys(outpost_keys, outpost_args.keys()) is False:
        raise CLIException("Invalid keys passed to outpost arguments.")

    modes = ["proxy", "forward_single", "forward_domain"]
    if provider_args['mode'] not in modes:
        raise CLIException(f'Unimplemented provider mode \'{provider_args["mode"]}\' selected.')
    
    with AuthentikAPI(args.host, args.port, args.token) as authentik:
        # Check provider is not already registered
        providers: dict = authentik.get_applications(full_list=True)
        for provider in providers:
            if args.name == provider["name"]:
                raise CLIException(f'The name {args.name} is already registered with a provider.')
            if f'https://{args.domain}' == provider["launch_url"]:
                raise CLIException(f'The domain {args.domain} is already registered with a provider.')

        # Fetch app template
        app_template: dict = __get_app_template(authentik, application_args['app_template'])
        
        # Fetch provider template
        provider_template: dict = __get_provider_template(authentik, provider_args['provider_template'])
        
        # Assemble parameters based on type
        if provider_args["mode"] == "forward_single":
            params: dict = {"name":args.name, "authorization_flow":provider_template["authorization_flow"], "external_host":f'https://{args.domain}',
                        "mode":provider_args["mode"], "token_validity":provider_args['token_validity']}
        
        # Create provider
        providerUuid: str = authentik.create_proxy_provider(params)['pk']

        params: dict={"name":args.name, "slug":__create_slug(args.name), "policy_engine_mode":app_template["policy_engine_mode"], "provider":providerUuid}
        if application_args['app_group'] is not None:
            params["group"] = application_args["app_group"]
        
        # Create application
        try:
            new_application: dict = authentik.create_application(params)
        except Exception as e:
            authentik.delete_provider(providerUuid)
            raise e
        
        try:
            # Apply policies
            template_policies: dict = authentik.get_policy_bindings(app_template['pk'])
            for policy in template_policies:
                params: dict={"target":new_application['pk'], "negate":policy["negate"], "enabled":policy['enabled'], "order":policy['order'], "timeout":policy['timeout']}
                if policy['policy'] is not None:
                    params['policy'] = policy['policy']
                if policy['group'] is not None:
                    params['group'] = policy['group']
                if policy['user'] is not None:
                    params['user'] = policy['user']

                authentik.create_policy_binding(params)
            
            # Add provider to the outpost
            outpost = __get_outpost(authentik, outpost_args["name"])
            
            providers: list=outpost["providers"]
            providers.append(providerUuid)
            params: dict={"providers":providers}
            authentik.update_outpost(outpost['pk'], params)
        except Exception as e:
            authentik.delete_application(new_application['slug'])
            authentik.delete_provider(providerUuid)
            raise e
        
def __remove_domain(args):
    with AuthentikAPI(args.host, args.port, args.token) as authentik:
        domain: Optional[dict] = __match_domain(authentik, args.domain, args.provider_type)
        if domain is None:
            raise CLIException(f'Failed to match the domain \'{args.domain}\'.')
        if authentik.delete_application(domain["assigned_application_slug"]) is False:
            raise CLIException(f'Failed to remove the application.')
        if authentik.delete_provider(domain['pk']) is False:
            raise CLIException(f'Failed to remove the provider.')

'''
    COMMAND HELPER METHODS
'''

def __match_domain(authentik: AuthentikAPI, domain: str, prov_type: str) -> Optional[dict]:
    types: list = ["proxy"] # TODO: Unimplemented type matching: "ldap", "oauth2", "saml"
    if prov_type not in types: return None
    
    providers: Optional[dict] = authentik.get_providers()
    if providers is None: return None

    provider = None
    for item in providers:
        detail: Optional[dict] = authentik.get_provider(item['pk'], prov_type)
        if detail is None: continue

        if prov_type == "proxy":
            if domain in detail['external_host'].split("/"):
                provider = detail
                break
    return provider

def __get_app_template(authentik: AuthentikAPI, name: str) -> dict:
    templates = authentik.get_applications(name, True)
    for template in templates:
        if template['name'] == name: return template

    raise CLIException(f'Failed to fetch application template \'{name}\'.')

def __get_provider_template(authentik: AuthentikAPI, name: str) -> dict:
    templates = authentik.get_providers(name)
    for template in templates:
        if template['name'] == name: return template
    
    raise CLIException(f'Failed to fetch provider template \'{name}\'.')

def __get_outpost(authentik: AuthentikAPI, name: str) -> dict:
    outposts: dict= authentik.get_outposts(name)
    for outpost in outposts:
        if outpost['name'] == name: return outpost
    
    raise CLIException(f'Failed to fetch output \'{name}\'.')

def __create_slug(name: str) -> str:
    slug = name.replace(' ', '-')
    slug = slug.lower()
    slug = re.sub(r'[^-a-zA-Z0-9_]', "", slug)
    return slug


if __name__ == "__main__":
    main()