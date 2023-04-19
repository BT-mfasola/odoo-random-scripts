import json
import sys
import argparse
import re
import time
from datetime import datetime, timezone, timedelta
import random
from pprint import pprint
import requests
from requests_oauthlib import OAuth2Session
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from oauthlib.oauth2 import BackendApplicationClient, InvalidClientError, TokenExpiredError
import inspect
# for more info on requests see https://requests.readthedocs.io/en/master/



class RestAPI:
    """This class got two different ways of authenticate solely to test those different ways with various
    different servers. Just to test the actual payloads requests, that should not be of concern.
    standard way is to use myapi.authenticate(), alternative way is to use myapi.get_auth()"""
    def __init__(self, auth_type=None, headers={}, client_id=None, client_secret=None, username=None, 
                    password=None, base_url=None, token_url=None, verbosity=0, readonly=False):
        self.base_url = base_url
        self.auth_type = auth_type
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.access_token = None
        self.headers = headers
        self.auth = None
        self.token_url = token_url
        self.token = None
        self.client = BackendApplicationClient(client_id=self.client_id)
        self.oauth = OAuth2Session(client=self.client)
        self.counter = 0
        self.verbosity = verbosity
        self.readonly = readonly

    def get_counter(self):
        return self.counter

    def route(self, url):
        if not url.startswith('http'):
            if not url.startswith('/'):
                url = f"{self.base_url}/{url}"
            else:
                url = f"{self.base_url}{url}"
            if self.verbosity > 2:
                print(f"building route with base {self.base_url} and endpoint {url}")
        return url


    def authenticate(self):
        if self.auth_type == 'basic':
            self.auth = HTTPBasicAuth(self.username, self.password)
        elif self.auth_type == 'digest':
            self.auth = HTTPDigestAuth(self.username, self.password)
        elif self.auth_type == 'oauth2':
            #auth = HTTPOauth2(self.get_access_token())
            if self.verbosity > 2:
                print(f"trying to get token from url {self.route(self.token_url)}")
            try:
                self.token = self.oauth.fetch_token(
                    token_url=self.route(self.token_url),
                    client_id=self.client_id, client_secret=self.client_secret
                )
            except InvalidClientError:
                # InvalidClientError: probably wrong credentials
                print("ERROR: got an 'invalid client' error from the server - please check your credentials")
                return False
            except requests.exceptions.ConnectionError:
                print("ERROR: connection error - please check the (auth) url")
                return False
            except Exception as e:
                raise e # re-raise all other exceptions
            if self.verbosity > 2:
                print(f"got token {self.token}")
        return True


    def get_auth(self):
        """Returns the correct requests auth handler base on the auth type or None if is not required"""
        auth = None
        if self.auth_type == 'basic':
            auth = HTTPBasicAuth(self.username, self.password)
        elif self.auth_type == 'digest':
            auth = HTTPDigestAuth(self.username, self.password)
        elif self.auth_type == 'oauth2':
            auth = HTTPOauth2(self._get_access_token())
        return auth


    def _get_access_token(self):
        """ Check if access token need to be (re)generated.
        We add a security time shift to assure the token does not expire within the
        time until the request will be sent.
        """
        if not self.access_token or \
                    self.token_expiration_date - timedelta(seconds=10) <= fields.Datetime.now():
            if self.verbosity > 2:
                print('request new token')
            self._generate_rest_token()

        return self.access_token


    def _generate_rest_token(self):
        """Generate Rest Token"""
        if self.auth_type == 'oauth2':
            if not (self.base_url and self.token_url and self.client_id and self.client_secret):
                raise Exception('Missing login parameter(s).')

            payload = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "data/all"
            }
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "accept": "application/json",
            }

            resp = requests.post(self.token_url, data=payload, headers=headers)

            if resp.status_code == 200:
                response = resp.json()
                self.access_token = response.get('access_token')
            else:
                raise Exception('Attempt to retrieve token failed.')


    def _exec_oauth(self, endpoint, type="GET", data={}):
        if self.verbosity > 2:
            print(f"query: {type} {self.route(endpoint)}")
        re_auth = False
        try:
            if type == "GET":
                response = self.oauth.get(self.route(endpoint), data=data)
            elif type == "POST" and not self.readonly:
                response = self.oauth.post(self.route(endpoint), data=data)
            elif type == "PUT" and not self.readonly:
                response = self.oauth.put(self.route(endpoint), data=data)
            elif type == "DELETE" and not self.readonly:
                response = self.oauth.delete(self.route(endpoint), data=data)
            else:
                print(f"INFO: not sending {type} requests to {self.route(endpoint)} in read-only mode!")
                response = None
        except TokenExpiredError: 
            # if the token expired, try to re-auth
            if self.verbosity > 0:
                print("INFO: token expired, try to re-auth and re-submit request")
            self.authenticate()
            self._exec_oauth(endpoint=endpoint, type=type, data=data)
        except requests.exceptions.ConnectionError:
            print("ERROR: connection error - please check the (host) url")
            return False
        except Exception as e:
            raise e # re-raise all other exceptions
        return response


    def _exec_other(self, endpoint, type="GET", data={}, json_data={}):
        if self.verbosity > 2:
            print(f"query: {self.route(endpoint)}")
        if type == "GET":
            response = requests.get(self.route(endpoint), data=data, headers=self.headers, auth=self.auth)
        elif type == "POST" and not self.readonly:
            response = requests.post(self.route(endpoint), data=data, headers=self.headers, auth=self.auth)
        elif type == "PUT" and not self.readonly:
            response = requests.put(self.route(endpoint), data=data, headers=self.headers, auth=self.auth)
        elif type == "DELETE" and not self.readonly:
            response = requests.delete(self.route(endpoint), data=data, headers=self.headers, auth=self.auth)
        else:
                print(f"INFO: not sending {type} requests to {self.route(endpoint)} in read-only mode!")
                response = None
        return response


    def execute(self, endpoint, type="GET", data={}, json_data={}):
        self.counter += 1
        if self.verbosity > 2:
            print(f"Payload for the {type} request to {endpoint}:")
            print(json.dumps(data, indent=2))
        if self.auth_type == "oauth2":
            response = self._exec_oauth(self.route(endpoint), type=type, data=data)
        else:
            response = self._exec_other(self.route(endpoint), type=type, data=data, json_data=json_data)
        status_code = None
        try:
            status_code = response.status_code
        except:
            # something went wrong
            print("ERROR: something went wrong sending the request")
            if self.verbosity > 2:
                pprint(inspect.getmembers(response))
            return []
        if status_code != 200:
            if self.verbosity > 0:
                print('Status Code: {}'.format(response.status_code))
                print('Reason: {}'.format(response.reason))
                if self.verbosity > 1:
                    print('Request: {}'.format(response.request))
                    print(inspect.getmembers(response.request))
                    print('Content:')
                    pprint(response._content)
                f = open("request_error.txt", "w")
                f.write(response._content.decode('utf-8'))
                f.close()
                print("wrote content to request_error.txt")
            #raise Exception("Response: {} [{}]".format(response.status_code, response.reason))
            return []
        else:
            if self.verbosity > 1:
                print(f"Response for the {type} request to {endpoint}:")
                print(json.dumps(response.json(), indent=2))
            return response.json()



class DataStructureSync:
    """This class can read a data structure including recursingly the generate or parse structures from Odoo 
    and save it as a json file or read a json file and create a new data structure including recusrively
    their generator and parser structures"""
    def __init__(self, verbosity=0, readonly=False, cred_file_name="default_credentials.json"):
        # object data
        self.odoo_api = None # this will hold the connection to Odoo after the api init
        self.cred_file_name = cred_file_name
        self.data_file_name = "{}.json"
        self.verbosity = verbosity
        self.readonly = readonly

        # default values to work with (or export as scafforld)
        self.connection = 'example_connection'
        self.host_url = "https://odoo.example.com"
        self.rest_api = "/api/v2"
        self.base_url = "https://odoo.example.com/api/v2"
        self.auth_type = "oauth2"
        self.client_id = "insert client id/key here"
        self.client_secret = "insert client secret here"
        self.token_url = 'https://odoo.example.com/api/v2/authentication/oauth2/token'
        self.odoo_api_version = ""
        self.odoo_server_serie= 0.0
        self.odoo_server_Version= "0.0+c"
        self.odoo_api_version_info = {}

        # format defaults
        self.dt_format_odoo = '%Y-%m-%d %H:%M:%S'
        self.dt_format_data = '%Y-%m-%dT%H:%M:%S.%fZ'

        # cached data for ir.model, ir.model.fields, res.language
        ''' The reason for this is that for these models there are m2o/m2m relations- which when importing
            in another system, the ids would generally differ. Hence those m2o/m2m must rather be stored with
            system-independently indentifiable data. In order not to query the same several times, a global
            cache would help '''
        self.data_structure_cache = {}
        self.ir_model_cache = {}
        self.ir_model_fields_cache = {}
        self.res_lang_cache = {}

        # lists of fields to be processed
        # data.structure fields
        self.data_structure_fields_simple = [
            'field_name',
            'is_execute_for_each_record',
            'is_for_specific_records',
            'name',
            'records_domain',
            'structure_type',
            'value_type',
        ]
        self.data_structure_fields_simple_14 = [ # new in version 14
            'delta_time',
            'delta_time_type',
        ]
        self.data_structure_fields_o2m = [
            'generator_ids',
            'parser_ids',
        ]
        self.data_structure_fields_m2o = [
            'child_id',
            'model_id',
        ]
        self.data_structure_fields_m2o_14 = [ # new in version 14
            'filter_date_field_id',
        ]
        self.data_structure_fields_meta = [
            '__last_update',
            'create_date',
            'create_uid',
            'write_date',
            'write_uid',
        ]
        self.data_structure_fields_no_import = [
            'display_name',
            'id',
            'model_name',
            #'test_result', # not needed and not present in all versions
        ]
        # generator.data.structure fields
        self.generator_structure_fields_simple = [
            'field_name',
            'is_execute_for_each_record',
            'is_for_specific_records',
            'is_keyword_dynamic',
            'is_required',
            'keyword',
            'keyword_type',
            'keyword_value',
            'records_domain',
            'sequence',
            'skip_if_value',
            'translation_for',
            'value',
            'value_type',
            'value_type_cast',
        ]
        self.generator_structure_fields_simple_14 = [ # new in version 14
            'date_format',
            'delta_time',
            'delta_time_type',
        ]
        self.generator_structure_fields_o2m = [
            'child_ids',
            'lang_mapping_ids',
        ]
        self.generator_structure_fields_m2o = [
            'lang_id',
            'model_id',
            # parent_id and structure_id are omitted intentionally
        ]
        self.generator_structure_fields_m2o_14 = [ # new in version 14
            'filter_date_field_id',
        ]
        self.generator_structure_fields_meta = [
            '__last_update',
            'create_date',
            'create_uid',
            'write_date',
            'write_uid',
        ]
        self.generator_structure_fields_no_import = [
            'display_name',
            'id',
            'model_name',
            'parent_id', # not technically read-only, but cannot be used when importing top-down
            'structure_value_type',
            'structure_id', # not technically read-only, but cannot be used when importing top-down
        ]
        # language.mappping fields
        self.language_mapping_fields_simple = [
            'keyword',
        ]
        self.language_mapping_fields_o2m = [
        ]
        self.language_mapping_fields_m2o = [
            'lang_id',
            # generator_id is omitted intentionally
        ]
        self.language_mapping_fields_meta = [
            '__last_update',
            'create_date',
            'create_uid',
            'write_date',
            'write_uid',
        ]
        self.language_mapping_fields_no_import = [
            'display_name',
            'id',
            'generator_id', # not technically read-only, but cannot be used when importing top-down
        ]
        # parser.data.structure fields
        self.parser_structure_fields_simple = [
            'keyword',
            'value_type',
        ]
        self.parser_structure_fields_o2m = [
            'child_ids',
        ]
        self.parser_structure_fields_m2m = [
        ]
        self.parser_structure_fields_m2o = [
            'field_id',
            'odoo_model_id',
            # parent_id and structure_id are omitted intentionally
        ]
        self.parser_structure_fields_meta = [
            '__last_update',
            'create_date',
            'create_uid',
            'write_date',
            'write_uid',
        ]
        self.parser_structure_fields_no_import = [
            'available_odoo_mapping_field_ids',
            'display_name',
            'id',
            'parent_id', # not technically read-only, but cannot be used when importing top-down
            'structure_id', # not technically read-only, but cannot be used when importing top-down
        ]


    def _get_model_fields(self, model=None, importable=False, simple=False, m2o=False, o2m=False, m2m=False,
                          meta=False, no_import=False):
        '''when search_reading the wanted fields - this helper method helps selecting the right ones.'''
        if not(importable or simple or m2o or o2m or m2m or meta or no_import):
            # by default return importable fields
            importable = True
        v14 = False
        if self.odoo_server_serie >= 14.0:
            v14 = True # use additional fields introduced in 14.0
        if model == 'data.structure':
            field_list = (self.data_structure_fields_simple if simple or importable else []) + \
                (self.data_structure_fields_simple_14 if (simple or importable) and v14 else []) + \
                (self.data_structure_fields_o2m if o2m or importable else []) + \
                (self.data_structure_fields_m2o if m2o or importable else []) + \
                (self.data_structure_fields_m2o_14 if (m2o or importable) and v14 else []) + \
                (self.data_structure_fields_meta if meta else []) + \
                (self.data_structure_fields_no_import if no_import else [])
        elif model == 'generate.data.structure':
            field_list = (self.generator_structure_fields_simple if simple or importable else []) + \
                (self.generator_structure_fields_simple_14 if (simple or importable) and v14 else []) + \
                (self.generator_structure_fields_o2m if o2m or importable else []) + \
                (self.generator_structure_fields_m2o if m2o or importable else []) + \
                (self.generator_structure_fields_m2o_14 if (m2o or importable) and v14 else []) + \
                (self.generator_structure_fields_meta if meta else []) + \
                (self.generator_structure_fields_no_import if no_import else [])
        elif model == 'parse.data.structure':
            field_list = (self.parser_structure_fields_simple if simple or importable else []) + \
                (self.parser_structure_fields_o2m if o2m or importable else []) + \
                (self.parser_structure_fields_m2o if m2o or importable else []) + \
                (self.parser_structure_fields_meta if meta else []) + \
                (self.parser_structure_fields_no_import if no_import else [])
        elif model == 'language.mapping':
            field_list = (self.language_mapping_fields_simple if simple or importable else []) + \
                (self.language_mapping_fields_o2m if o2m or importable else []) + \
                (self.language_mapping_fields_m2o if m2o or importable else []) + \
                (self.language_mapping_fields_meta if meta else []) + \
                (self.language_mapping_fields_no_import if no_import else [])
        else:
            field_list = []
        return field_list


    def load_credentials(self, cred_file_name=None, connection=None):
        if not(cred_file_name):
            cred_file_name = self.cred_file_name
        if not(cred_file_name):
            raise Exception("Error: no credentials file given")
        # read credentials
        with open(cred_file_name) as credentials_file:    
            credentials = json.load(credentials_file)
            if not credentials:
                raise Exception("ERROR: could not load credentials file data. aborting.")
        if connection in credentials:
            # use connection parameters from credentials file if they exist and sanitize them
            if 'host_url' in credentials[connection]:
                self.host_url = credentials[connection]['host_url']
                if not self.host_url.startswith('http'):
                    self.host_url = f"https://{self.host_url}"
                if self.host_url[-1:] == '/':
                    self.host_url = self.host_url[:-1]
                if self.verbosity > 2:
                    print(f"using host {self.host_url}")
            if 'rest_api' in credentials[connection]:
                self.rest_api = credentials[connection]['rest_api']
                if not self.rest_api.startswith('/'):
                    self.rest_api = f"/{self.rest_api}"
                if self.rest_api[-1:] == '/':
                    self.rest_api = self.rest_api[:-1]
                if self.verbosity > 2:
                    print(f"using api {self.rest_api}")
            self.base_url = f"{self.host_url}{self.rest_api}"
            if self.verbosity > 2:
                print(f"using base url {self.base_url}")
            if 'client_id' in credentials[connection]:
                self.client_id = credentials[connection]['client_id']
                if self.verbosity > 2:
                    print(f"using client_id {self.client_id}")
            if 'client_secret' in credentials[connection]:
                self.client_secret = credentials[connection]['client_secret']
            if 'token_url' in credentials[connection]:
                self.token_url = credentials[connection]['token_url']
            else:
                self.token_url = f"{self.base_url}/authentication/oauth2/token" 
            if self.verbosity > 2:
                print(f"using token url {self.token_url}")
        else:
            raise Exception("ERROR: could not find connection {} in credentials file {}".format(
                                connection, cred_file_name))
        return True


    def write_scaffold_credentials(self, cred_file_name='example_credentials.json', 
                                   connection='example_connection'):
        credentials = {
          "odoo-16_demo": {
            "host_url": "https://odoo-16.example.com",
            "rest_api": "/api/v2",
            "client_id": "{put client id/key here}",
            "client_secret": "{put client secret here}"
          },
          "odoo-15_demo": {
            "host_url": "https://odoo-15.example.com",
            "rest_api": "/api/v1",
            "client_id": "{put client id/key here}",
            "client_secret": "{put client secret here}"
          },
          "odoo-14_demo": {
            "host_url": "https://odoo-14.example.com",
            "rest_api": "/api/v1",
            "client_id": "{put client id/key here}",
            "client_secret": "{put client secret here}"
          },
          "odoo-13_demo": {
            "host_url": "https://odoo-13.example.com",
            "rest_api": "/api",
            "client_id": "{put client id/key here}",
            "client_secret": "{put client secret here}"
          },
          "odoo-xy_demo": {
            "host_url": "https://odoo-xy.example.com",
            "rest_api": "/api",
            "token_url": "https://odoo-xy.example.com/api/authentication/oauth2/token",
            "client_id": "{put client id/key here}",
            "client_secret": "{put client secret here}"
          }
        }

        with open(cred_file_name, 'w') as credentials_file:
            json.dump(credentials, credentials_file, indent=2)
        print(f"INFO: a scaffold credentials file has been written to {cred_file_name}")


    def list_connections(self, cred_file_name=None):
        if not cred_file_name:
            cred_file_name = self.cred_file_name
        if not cred_file_name:
            raise Exception("Warning: no credentials file given, no connections can be listed")
        # read credentials
        with open(cred_file_name) as credentials_file:
            credentials = json.load(credentials_file)
            if not credentials:
                raise Exception("Warning: could not load credentials file data, no connections found.")
        for connection in credentials:
            print(connection)
        return


    def init_api(self):
        # init API
        if self.verbosity > 0:
            print("INFO: Initialize API and authenticate")
        self.odoo_api = RestAPI(auth_type=self.auth_type, headers={}, client_id=self.client_id, 
                        client_secret=self.client_secret, base_url=self.base_url, 
                        token_url=self.token_url, readonly=self.readonly,
                        verbosity=self.verbosity)
        #self.odoo_api._get_access_token() # this is just for testing different libraries
        if not self.odoo_api.authenticate():
            return False

        # get info about the api - will help catching version specific differences
        api = self.odoo_api.execute('')
        if not api:
            return False
        user = self.odoo_api.execute('/user')
        self.odoo_api_version = api.get('api_version', None)
        self.odoo_server_version= api.get('server_version', None)
        self.odoo_api_version_info = api.get('server_version_info', None)
        try:
            self.odoo_server_serie= float(api.get('server_serie', None))
        except:
            self.odoo_server_serie = None

        if self.verbosity > 1:
            print(f"INFO: successfully authenticated with user {user.get('name', 'unknown')} on Odoo "
                  f"version {self.odoo_server_version}")
        return True


    def get_record_by_id(self, model='', rec_id=0, fields=[]):
        ''' takes a model, a record id and a list of fields
            returns a dict with the records' values for the requested fields
            if no valid response is received still a dict with all the fields and empty values is returned'''
        data = {
            'model': model,
            'domain': json.dumps([['id', '=', rec_id]]),
            'fields': json.dumps(fields),
            'limit': 1
        }
        if self.verbosity > 2:
            print(f"query record {rec_id} of model {model} for fields {fields}")
        response = self.odoo_api.execute('search_read', type="GET", data=data)
        if response:
            return next(iter(response))
        else:
            return {f: None for f in fields}


    def get_data_structure_by_id(self, data_structure_id=False):
        ''' takes one data structure id and returns the data.structure.name
            can deal with the id as integer, list or tuple to make calling it from response easier
            uses the cache to avoid multiple requests for the same data'''
        if not data_structure_id:
            return False
        data_structure_id = data_structure_id[0] if type(data_structure_id) in [list, tuple] \
                                                 else data_structure_id
        if not data_structure_id in self.data_structure_cache:
            self.data_structure_cache[data_structure_id] = self.get_record_by_id(model='data.structure',
                                                rec_id=data_structure_id, fields=['id', 'name'])
        return self.data_structure_cache[data_structure_id]['name']


    def get_model_by_id(self, model_id=0):
        ''' takes one model id and returns the ir.model.model
            can deal with the id as integer, list or tuple to make calling it from response easier
            uses the cache to avoid multiple requests for the same data'''
        if not model_id:
            return False
        model_id = model_id[0] if type(model_id) in [list, tuple] else model_id
        if not model_id in self.ir_model_cache:
            self.ir_model_cache[model_id] = self.get_record_by_id(model='ir.model', rec_id=model_id,
                                                fields=['id', 'name', 'model'])
        return self.ir_model_cache[model_id]['model']


    def get_field_by_id(self, field_id=0):
        ''' takes one field id and returns the ir.model.field's name and the model_id.model
            can deal with the id as integer, list or tuple to make calling it from response easier
            uses the cache to avoid multiple requests for the same data'''
        if not field_id:
            return False
        field_id = field_id[0] if type(field_id) in [list, tuple] else field_id
        if not field_id in self.ir_model_fields_cache:
            field_record = self.get_record_by_id(model='ir.model.fields', rec_id=field_id,
                                           fields=['id', 'name', 'model_id'])
            field_record['model'] = self.get_model_by_id(model_id=field_record['model_id'])
            self.ir_model_fields_cache[field_id] = field_record
        return self.ir_model_fields_cache[field_id]['name'], self.ir_model_fields_cache[field_id]['model']


    def get_lang_by_id(self, lang_id=0):
        ''' takes one lang id and returns the res.language's code
            can deal with the id as integer, list or tuple to make calling it from response easier
            uses the cache to avoid multiple requests for the same data'''
        if not lang_id:
            return False
        lang_id = lang_id[0] if type(lang_id) in [list, tuple] else lang_id
        if not lang_id in self.res_lang_cache:
            self.res_lang_cache[lang_id] = self.get_record_by_id(model='res.lang', rec_id=lang_id,
                                                fields=['id', 'name', 'code'])
        return self.res_lang_cache[lang_id]['code']


    def export_structures(self, data_structure_names=[], data_file_name=None, 
                        export_meta=False, export_no_import=False, export_ilike=False):
        ''' query all structures identified by the nargs list of data structure names optionally matched with
            ilike and call export_structures() to export each of the result individually.
            for each export the placeholder {} in the data file name is replaced with a sanitized data
            structure name if present, otherwise each export would overwrite the last one (todo: warn...)'''
        operator = 'ilike' if export_ilike else '='
        domain = (len(data_structure_names)-1) * ['|'] + [['name', operator, s] for s in data_structure_names]
        if self.verbosity > 1:
            print(f"INFO: data.structure to export {domain}")
        data = {
            'model': "data.structure",
            'domain': json.dumps(domain),
            'fields': json.dumps(['name']),
        }
        response = self.odoo_api.execute('search_read', type="GET", data=data)
        for r in response:
            structure = r.get('name', '')
            file_name = re.sub(r'[^0-9a-zA-Z]',r'',structure)
            if data_file_name:
                file_name = data_file_name.replace('{}',file_name)
            if file_name[-5:].lower() != '.json':
                file_name = f"{file_name}.json"
            if self.verbosity > 0:
                print(f"exporting data structure '{structure}' to file '{file_name}'")
            self.export_structure(data_structure_name=structure, data_file_name=file_name, 
                                    export_meta=export_meta, export_no_import=export_no_import)


    def export_structure(self, data_structure_name=None, data_file_name=None,
                            export_meta=False, export_no_import=False):
        ''' exports a single data structure in whole to the file specified
            the generator and parser sub-structures are derived recursively
            the resulting json stores each record in a flat structure that can be used in various ways
            for related records that are not exported (model, fields, language), identifiable fields other
            than their ID is stored too, because the ids would generally be different in another system
            (especially when using the script to export from test systems and import to prod systems)'''
        # building the list of fields to be exported depending on args
        data_structure_fields_export = self._get_model_fields(model='data.structure', importable=True,
            meta=export_meta, no_import=export_no_import)
        generator_structure_fields_export = self._get_model_fields(model='generate.data.structure',
            importable=True, meta=export_meta, no_import=export_no_import)
        parser_structure_fields_export = self._get_model_fields(model='parse.data.structure', importable=True,
            meta=export_meta, no_import=export_no_import)
        language_mapping_fields_export = self._get_model_fields(model='language.mapping', importable=True,
            meta=export_meta, no_import=export_no_import)

        # holding the final data structure to export
        data_structure = {}

        # first get some meta-data that better allows to identify the exported data if ever necessary
        data_structure['api'] = self.odoo_api.execute('')
        data_structure['user'] = self.odoo_api.execute('/user')
        data_structure['host'] = self.host_url

        # get main data structure
        if self.verbosity > 1:
            print(f"looking for and exporting the data.structure named {data_structure_name}")
        data = {
            'model': "data.structure",
            'domain': json.dumps([['name', '=', data_structure_name]]),
            'fields': json.dumps(data_structure_fields_export),
            'limit': 1
        }
        response = self.odoo_api.execute('search_read', type="GET", data=data)
        if response:
            data_structure_data = next(iter(response))
            # the m2o to model and field would generally have different ids in other systems
            # so get identifiable data from those models to be stored alongside the ids
            child_id = data_structure_data.get('child_id', False)
            if child_id:
                data_structure_data['child_id.name'] = \
                        self.get_data_structure_by_id(data_structure_id=child_id)
            model_id = data_structure_data.get('model_id', False)
            if model_id:
                data_structure_data['model_id.model'] = self.get_model_by_id(model_id=model_id)
            field_id = data_structure_data.get('filter_date_field_id', False)
            if field_id:
                data_structure_data['filter_date_field_id.name'],  \
                  data_structure_data['filter_date_field_id.model']  = self.get_field_by_id(field_id=field_id)
            # add it to the final data structure
            data_structure['data_structure'] = data_structure_data

            # get all generator structures
            generator_structures = {}
            for generator_id in data_structure_data.get('generator_ids'):
                generator_structures.update(self.read_generator_structure(generator_id = generator_id, 
                            fields = generator_structure_fields_export))
            data_structure['generator_structures'] = generator_structures

            # get all language mappings on the generators
            language_mappings = {}
            for generator_id in generator_structures:
                mapping_ids = generator_structures[generator_id].get('lang_mapping_ids', [])
                if self.verbosity > 2:
                    print(f"checking generator {generator_id} for language mappings and found {mapping_ids}")
                if mapping_ids:
                    language_mappings.update(self.read_language_mappings(
                            mapping_ids = mapping_ids, fields = language_mapping_fields_export))
            data_structure['language_mappings'] = language_mappings

            # get all parser structures
            parser_structures = {}
            for parser_id in data_structure_data.get('parser_ids'):
                parser_structures.update(self.read_parser_structure(parser_id = parser_id,
                            fields = parser_structure_fields_export))
            data_structure['parser_structures'] = parser_structures
        else:
            if self.verbosity > 1:
                print('INFO: did not get any response, finishing')

        # write json
        if self.verbosity > 1:
            print("got the following data in the end")
            pprint(data_structure)
        with open(data_file_name, 'w') as data_structure_file:
            json.dump(data_structure, data_structure_file, indent=2)
        if self.verbosity > 0:
            print(f"INFO: the data structure {data_structure_name} "
                  f"has been read in {self.odoo_api.get_counter()} requests "
                  f"and was written to the file {data_file_name}")


    def read_generator_structure(self, generator_id=None, fields=[]):
        generator_structures = {}
        if self.verbosity > 1:
            print(f"looking for and exporting the generate.data.structure with id {generator_id}")
        data = {
            'model': "generate.data.structure",
            'domain': json.dumps([['id', '=', generator_id]]),
            'fields': json.dumps(fields),
            'limit': 1
        }
        response = self.odoo_api.execute('search_read', type="GET", data=data)
        if response:
            generator_structure = next(iter(response))
            # the m2o to model, field and language would generally have different ids in other systems
            # so get identifiable data from those models to be stored alongside the ids
            model_id = generator_structure.get('model_id', None)
            if model_id:
                generator_structure['model_id.model'] = self.get_model_by_id(model_id=model_id)
            field_id = generator_structure.get('filter_date_field_id', None)
            if field_id:
                generator_structure['filter_date_field_id.name'],  \
                  generator_structure['filter_date_field_id.model']  = self.get_field_by_id(field_id=field_id)
            lang_id = generator_structure.get('lang_id', None)
            if lang_id:
                generator_structure['lang_id.code'] = self.get_lang_by_id(lang_id=lang_id)
            generator_structures = {generator_id: generator_structure}

            # get all sub generator structures
            for sub_generator_id in generator_structure.get('child_ids'):
                generator_structures.update(self.read_generator_structure(generator_id=sub_generator_id))
        return generator_structures


    def read_language_mappings(self, mapping_ids=[], fields=[]):
        language_mappings = {}
        if self.verbosity > 1:
            print(f"looking for and exporting the language.mapping with ids {mapping_ids}")
        if not mapping_ids:
            return {}
        data = {
            'model': "language.mapping",
            'domain': json.dumps([['id', '=', mapping_ids]]),
            'fields': json.dumps(fields),
        }
        response = self.odoo_api.execute('search_read', type="GET", data=data)
        if response:
            for language_mapping in response:
                # the m2o to language would generally have different ids in other systems
                # so get identifiable data from that model to be stored alongside the ids
                lang_id = language_mapping.get('lang_id', None)
                if lang_id:
                    language_mapping['lang_id.code'] = self.get_lang_by_id(lang_id=lang_id)
                language_mappings.update({language_mapping.get('id'): language_mapping})
        return language_mappings


    def read_parser_structure(self, parser_id=None, fields=[]):
        parser_structures = {}
        if self.verbosity > 1:
            print(f"looking for and exporting the parse.data.structure with id {parser_id}")
        data = {
            'model': "parse.data.structure",
            'domain': json.dumps([['id', '=', parser_id]]),
            'fields': json.dumps(fields),
            'limit': 1
        }
        response = self.odoo_api.execute('search_read', type="GET", data=data)
        if response:
            parser_structure = next(iter(response))
            # the m2o to model, field and language would generally have different ids in other systems
            # so get identifiable data from those models to be stored alongside the ids
            model_id = parser_structure.get('odoo_model_id', None)
            if model_id:
                parser_structure['odoo_model_id.model'] = self.get_model_by_id(model_id=model_id)
            field_id = parser_structure.get('field_id', None)
            if field_id:
                parser_structure['field_id.name'],  \
                  parser_structure['field_id.model']  = self.get_field_by_id(field_id=field_id)
            parser_structures = {parser_id: parser_structure}

            # get all sub parser structures
            for sub_parser_id in parser_structure.get('child_ids'):
                parser_structures.update(self.read_parser_structure(parser_id=sub_parser_id))
        return parser_structures


    def get_record_id_by_domain(self, model='', domain=[]):
        ''' takes a model and a search domain to return the first id found
            if no valid response is received False is returned'''
        data = {
            'model': model,
            'domain': json.dumps(domain),
            'limit': 1
        }
        if self.verbosity > 2:
            print(f"query record matching seach domain {domain} of model {model} for it's id")
        response = self.odoo_api.execute('search', type="GET", data=data)
        if response:
            return next(iter(response))
        else:
            return False


    def get_data_structure_id_by_name(self, name=False):
        ''' takes a data structure's name to return the target system's data structure id
            uses the cache to avoid multiple requests for the same data'''
        if not name:
            return False
        if not name in self.data_structure_cache:
            self.data_structure_cache[name] = self.get_record_id_by_domain(model='data.structure',
                                                domain=[['name', '=', name]])
        if not self.data_structure_cache[name]:
            raise Exception(f"ERROR: on the target system no id for data structure {name} "
                             "could be found, aborting")
        return self.data_structure_cache[name]


    def get_model_id_by_model(self, model=False):
        ''' takes a model's model to return the target system's model id
            uses the cache to avoid multiple requests for the same data'''
        if not model:
            return False
        if not model in self.ir_model_cache:
            self.ir_model_cache[model] = self.get_record_id_by_domain(model='ir.model',
                                                domain=[['model', '=', model]])
        if not self.ir_model_cache[model]:
            raise Exception(f"ERROR: on the targes system no id for model {model} could be found, aborting")
        return self.ir_model_cache[model]


    def get_field_id_by_name_model(self, name=False, model=False):
        ''' takes a field's name and it's model_id's model to return the id of the field in the target system
            uses the cache to avoid multiple requests for the same data'''
        if not name or not model:
            return False
        field = f"{model}.{name}"
        if not field in self.ir_model_fields_cache:
            model_id = self.get_model_id_by_model(model=model)
            self.ir_model_fields_cache[field] = self.get_record_id_by_domain(model='ir.model.fields',
                                                domain=[['name','=',name],['model', '=', model]])
        if not self.ir_model_fields_cache[field]:
            raise Exception(f"ERROR: on the targes system no id for field {field} could be found, aborting")
        return self.ir_model_fields_cache[field]


    def get_lang_id_by_code(self, code=False):
        ''' takes a lang's code to return the target system's lang id
            uses the cache to avoid multiple requests for the same data'''
        if not code:
            return False
        if not code in self.res_lang_cache:
            self.res_lang_cache[code] = self.get_record_id_by_domain(model='res.lang',
                                                domain=[['code', '=', code]])
        return self.res_lang_cache[code]


    def create_structure(self, data_structure_name=None, data_file_name=None):
        if not(data_structure_name):
            raise Exception("WARNING: no data structure name given - will use the one found in the data")
        if not(data_file_name):
            data_file_name = self.data_file_name
        if not(data_file_name):
            raise Exception("ERROR: no data file given")

        # first check if the data structure with the given name already exists.
        # if so, suggest to use the update method instead (not automatically switching, might be unintended)
        data_structure_data = None
        if self.verbosity > 1:
            print(f"looking for an existing data.structure named {data_structure_name}")
        data = {
            'model': "data.structure",
            'domain': json.dumps([['name', '=', data_structure_name]]),
            'fields': json.dumps(self._get_model_fields('data.structure', importable=True)),
            'limit': 1
        }
        response = self.odoo_api.execute('search_read', type="GET", data=data)
        if response:
            print(f"ERROR: There is already an existing data.structure named {data_structure_name}, "
                   "no other structure can be created with that name. Consider changing the name or"
                   "using the update function if so desired.")
            return False

        # read data file
        with open(data_file_name) as data_structure_file:    
            data_structure = json.load(data_structure_file)
            if not data_structure:
                raise Exception(f"ERROR: could not load data structure from file {data_file_name}. aborting.")
        if self.verbosity > 1:
            print("Loaded data:")
            pprint(data_structure)
        if not 'data_structure' in data_structure:
            print(f"ERROR: could not find data_structure in data from {data_file_name}, aborting.")

        ''' general idea on how to process the read data to create the structure:
            directly create the whole structure for one create call to in Odoo by making use of the Odoo
            ORM provided commands to manipulate o2m and m2m records directly:
                for editing/updating/deleting one2many and many2many please refer below syntaxes :
                (0, 0, { values }) link to a new record that needs to be created with the given values
                        dictionary
                (1, ID, { values }) update the linked record with id = ID (write values on it)
                (2, ID) remove and delete the linked record with id = ID (calls unlink on ID, that will delete
                        the object completely, and the link to it as well)
                (3, ID) cut the link to the linked record with id = ID (delete the relationship between the
                        two objects but does not delete the target object itself)
                (4, ID) link to existing record with id = ID (adds a relationship)
                (5) unlink all (like using (3,ID) for all linked records)
                (6, 0, [IDs]) replace the list of linked IDs (like using (5) then (4,ID) for each ID in the
                              list of IDs)
            hence for o2m fields create new records on the fly using the Odoo commands:
              o2m_field_ids = [(0, 0, {'field1': 'value_A1', 'field2': 'value_A2'})
                               (0, 0, {'field1': 'value_B1', 'field2': 'value_B2'})]
            for m2o fields where existing records are linked, the ids have to be queried while building the
            structure
            currently there are no m2m records to be imported - if there were a combination of those two
            processes would be needed;
            meta and no-import fields are not imported'''

        # start with the simple fields
        data_structure_values = {k: v for k, v in data_structure['data_structure'].items() \
                                        if k in self.data_structure_fields_simple}

        # the m2o fields need the record ids of the target system, so those have to be obtained if set
        child_name = data_structure['data_structure'].get('child_id.name', False)
        if child_name:
            data_structure_values['child_id'] = self.get_data_structure_id_by_name(name=child_name)
        field_name = data_structure['data_structure'].get('filter_date_field_id.name', False)
        field_model = data_structure['data_structure'].get('filter_date_field_id.model', False)
        if field_name and field_model:
            data_structure_values['filter_date_field_id'] = self.get_field_id_by_name_model( \
                                                             name=field_name, model=field_model)
        model_model = data_structure['data_structure'].get('model_id.model', False)
        if model_model:
            data_structure_values['model_id'] = self.get_model_id_by_model(model=model_model)

        # the o2m relations are added by adding the tuples with the instruction, id and data
        data_structure_values.update({k: [] for k in self.data_structure_fields_o2m})
        if 'generator_structures' in data_structure and data_structure['generator_structures']:
            for generator_id in data_structure['data_structure'].get('generator_ids', []):
                data_structure_values['generator_ids'] += [(0, 0, 
                                self.create_generator_tuple(generator_id=str(generator_id), 
                                generator_structures=data_structure['generator_structures'],
                                language_mappings=data_structure['language_mappings'])
                                )]
        if 'parser_structures' in data_structure and data_structure['parser_structures']:
            for parser_id in data_structure['data_structure'].get('parser_ids', []):
                data_structure_values['parser_ids'] += [(0, 0, 
                                self.create_parser_tuple(parser_id=str(parser_id), 
                                parser_structures=data_structure['parser_structures'])
                                )]

        # setting the required new name
        if data_structure_name:
            data_structure_values['name'] = data_structure_name

        # this should be directly creatable in Odoo
        if self.verbosity > 1:
            print(f"now creating new data structure {data_structure_name} with the following values:")
            pprint(data_structure_values)
        data = {
            'model': "data.structure",
            'values': json.dumps(data_structure_values),
        }
        response = self.odoo_api.execute('create', type="POST", data=data)
        if response:
            print(f"Result: a new data structure has been created with id {response}")
        else:
            print("WARNING: there seems to have been a problem creating the structure in Odoo, "
                  "check the previous messages or increase verbosity.")


    def create_generator_tuple(self, generator_id=None, generator_structures={}, language_mappings={}):
        if self.verbosity > 2:
            print(f"create_generator_tuple: build generator {generator_id} "
                   "from {generator_structures.keys()}")
        if not generator_id or not generator_structures or not generator_id in generator_structures:
            print(f"WARNING: create_generator_tuple: missing data for generator_id {generator_id}")
            return []
        # the simple fields are added as stored
        generator_structure = {k: v for k, v in generator_structures[generator_id].items() 
                                        if k in self.generator_structure_fields_simple}

        # the m2o fields need the record ids of the target system, so those have to be obtained if set
        field_name = generator_structures[generator_id].get('filter_date_field_id.name', False)
        field_model = generator_structures[generator_id].get('filter_date_field_id.model', False)
        if field_name and field_model:
            generator_structure['filter_date_field_id'] = self.get_field_id_by_name_model( \
                            name=field_name, model=field_model)
        lang_code = generator_structures[generator_id].get('lang_id.code', False)
        if lang_code:
            generator_structure['lang_id'] = self.get_lang_id_by_code(code=lang_code)
        model_model = generator_structures[generator_id].get('model_id.model', False)
        if model_model:
            generator_structure['model_id'] = self.get_model_id_by_model(model=model_model)

        # for the o2m first empty lists are added, to populate them next
        generator_structure.update({k: [] for k in self.generator_structure_fields_o2m})

        # for the language mapping o2m new records are added using the tuples
        for language_mapping in generator_structures[generator_id].get('lang_mapping_ids', []):
            lang_code = language_mappings[str(language_mapping)].get('lang_id.code', False)
            if lang_code:
                generator_structure['lang_mapping_ids'] += [(0, 0, {
                            'keyword': language_mappings[str(language_mapping)]['keyword'],
                            'lang_id': self.get_lang_id_by_code(code=lang_code),
                            })]

        # for the o2m child_ids list are populated recursively
        for child_id in generator_structures[generator_id].get('child_ids', []):
            generator_structure['child_ids'] += [(0, 0, 
                                self.create_generator_tuple(generator_id=str(child_id), 
                                generator_structures=generator_structures, 
                                language_mappings=language_mappings))]
        return generator_structure


    def create_parser_tuple(self, parser_id=None, parser_structures = {}):
        if self.verbosity > 2:
            print(f"create_parser_tuple: build parser {parser_id} from {parser_structures.keys()}")
        if not parser_id or not parser_structures or not parser_id in parser_structures:
            print(f"WARNING: create_parser_tuple: missing data for parser_id {parser_id}")
            return []
        # the simple fields are added as stored
        parser_structure = {k: v for k, v in parser_structures[parser_id].items() 
                                        if k in self.parser_structure_fields_simple}

        # the m2o fields need the record ids of the target system, so those have to be obtained if set
        field_name = parser_structures[parser_id].get('field_id.name', False)
        field_model = parser_structures[parser_id].get('field_id.model', False)
        if field_name and field_model:
            parser_structure['field_id'] = self.get_field_id_by_name_model( \
                            name=field_name, model=field_model)
        model_model = parser_structures[parser_id].get('odoo_model_id.model', False)
        if model_model:
            parser_structure['odoo_model_id'] = self.get_model_id_by_model(model=model_model)

        # for the o2m first empty lists are added, to populate them next
        parser_structure.update({k: [] for k in self.parser_structure_fields_o2m})

        # for the o2m child_ids list are populated recursively
        for child_id in parser_structures[parser_id].get('child_ids', []):
            parser_structure['child_ids'] += [(0, 0, self.create_parser_tuple(parser_id=str(child_id), 
                                parser_structures=parser_structures))]
        return parser_structure


    def update_structure(self, data_structure_name=None, data_file_name=None, unlink_records=False):
        ''' update is upsert really, as for non-existing data structures a new one will be created
            automatically, if not inhibited.
            additionally the unlink-records flag will used to determine if records found on the target system
            but are not in the stored data should be unlinked or not.'''
        print(f"WARNING: updating structures in Odoo isn't implemented yet")
        return False



#################
# main
#################


# functions for subparser
def export_structure(odoosync, args):
    odoosync.export_structures(data_structure_names=args.structure, data_file_name=args.datafile, 
                            export_meta=args.export_meta, export_no_import=args.export_no_import, 
                            export_ilike=args.export_ilike)

def create_structure(odoosync, args):
    odoosync.create_structure(data_structure_name=args.structure, data_file_name=args.datafile)

def update_structure(odoosync, args):
    print("WARNING: updating an existing data structure isn't implemented yet")
    return False
    odoosync.update_structure(data_structure_name=args.structure, data_file_name=args.datafile,
                            unlink = not(args.preserve_records))

def scaffold_credentials(odoosync, args):
    odoosync.write_scaffold_credentials(cred_file_name='example_credentials.json')

def list_connections(odoosync, args):
    odoosync.list_connections(cred_file_name=args.credentials_file)


# parser for the command line input
def main():
    parser = argparse.ArgumentParser(description="Export / Import tool to read a data generator from Odoo "
                        "recursively and save it as a json file - or to read a json file and create a data "
                        "structure in Odoo recursively.")

    # main / common parser elements
    parser.add_argument("-r", "--read-only", action="store_true", 
                        help="do not send / update data to Odoo, just simulate, data can be read.")
    parser.add_argument("-c", "--credentials-file", action="store", default='default_credentials.json',
                        help="specify the json file to read credentials from, defaults to "
                        "default_credentials.json")
    parser.add_argument("-v", "--verbosity", action="count", default=0,
                        help="the script by default only prints warnings and errors; increase verbosity to "
                        "show the successfully exported structures (v), more details, like received data "
                        "(vv), even more details like also sent payloads (vvv), everything (vvvv)")

    # add subparsers for individual functions: scaffold, export, create, update
    subparsers = parser.add_subparsers(title="command",
                        description="what the script should do",
                        help="the main command to define if a data structure should be exported from Odoo or "
                            "if a new data structure should be created in Odoo or to scaffold a creentials "
                            "file. use 'connection command --help' for command specific arguments")

    # arguments to export a data structure from Odoo and save it to the local json file
    parser_export = subparsers.add_parser('export', help="this will search for a data structure identified "
                        "by it's name and will read it recursively and store it in a json file")
    parser_export.add_argument("connection", help="the name of a connection to be used; the detailed "
                        "connection parameters must be stored in a file containing the connection details "
                        "and credentials as a dictionary stored in a json format. use --credentials-file to "
                        "use a specific file, otherwise a default file named default_credentials.json will "
                        "be used. Use the command scaffold to output an example credentials file to "
                        "example_credentials.json.")
    parser_export.add_argument("structure", nargs='*', help="the name(s) of the data structure to be "
                        "exported from Odoo. Takes a number of names. Omit to export all data structures "
                        "present, in which case '{}' in the data file name can be used as a placeholder for "
                        "the structure's sanitized name.")
    parser_export.add_argument("-d", "--datafile", action="store", default='{}.json',
                        help="specify the json file to write the data structure to, defaults to {}.json. "
                        "the placeholder '{}' will be replaced with a sanitized structure name.")
    parser_export.add_argument("-i", "--export-ilike", action="store_true",  default=False,
                        help="yield all structures partially matching the given name. "
                        "Default is a full match.")
    parser_export.add_argument("-m", "--export-meta", action="store_true",  default=False,
                        help="also export meta data")
    parser_export.add_argument("-n", "--export-no-import", action="store_true",  default=False,
                        help="also export non-importable fields")
    parser_export.set_defaults(func=export_structure, init_api=True)

    # arguments to create a data structure in Odoo using data from the local json file
    parser_create = subparsers.add_parser('create', help="this will read the data from the local json file "
                        "and create a new data structure in Odoo recursively")
    parser_create.add_argument("connection", help="the name of a connection to be used; the detailed "
                        "connection parameters must be stored in a file containing the connection details "
                        "and credentials as a dictionary stored in a json format. use --credentials-file to "
                        "use a specific file, otherwise a default file named default_credentials.json will "
                        "be used. Use the command scaffold to output an example credentials file to "
                        "example_credentials.json.")
    parser_create.add_argument("datafile", help="specify the json file to read the data structure from.")
    parser_create.add_argument("structure", help="the name of the data structure to be created in Odoo. "
                        "Note that there must not be a data structure with the same name already.")
    parser_create.set_defaults(func=create_structure, init_api=True)

    # arguments to update a data structure in Odoo using data from the local json file
    parser_update = subparsers.add_parser('update', help="this will read the data from the local json file "
                        "and update an existing data structure in Odoo recursively")
    parser_update.add_argument("connection", help="the name of a connection to be used; the detailed "
                        "connection parameters must be stored in a file containing the connection details "
                        "and credentials as a dictionary stored in a json format. use --credentials-file to "
                        "use a specific file, otherwise a default file named default_credentials.json will "
                        "be used. Use the command scaffold to output an example credentials file to "
                        "example_credentials.json.")
    parser_update.add_argument("datafile", help="specify the json file to read the data structure from.")
    parser_update.add_argument("structure", help="the name of the data structure to be updated in Odoo.")
    parser_update.add_argument("-p", "--preserve-records", action="store_true",  default=False,
                        help="additional generator or parser records in the target system are kept even if"
                        "not in the stored data structure - otherwise they are unlinked.")
    parser_update.set_defaults(func=update_structure, init_api=True)

    # scaffold a new example credentials file
    parser_scaffold = subparsers.add_parser('scaffold', help="export an example credentials file to "
                        "example_credentials.json")
    parser_scaffold.set_defaults(func=scaffold_credentials, init_api=False, datafile=None)

    # scaffold a new example credentials file
    parser_list_cred = subparsers.add_parser('list', help="list connection tags in the credentials file.")
    parser_list_cred.set_defaults(func=list_connections, init_api=False, datafile=None)


    # parse the arguments
    args = parser.parse_args()

    if args.credentials_file and args.verbosity > 1:
        print(f"INFO: will use credentials file {args.credentials_file}")
    if args.datafile and args.verbosity > 1:
        print(f"INFO: will use data file {args.datafile}")


    # execute the requested command
    if 'func' in args:
        # init the sync object
        odoosync = DataStructureSync(cred_file_name=args.credentials_file or 'default_credentials.json', 
                        verbosity=args.verbosity, readonly=args.read_only)
        if args.init_api:
            # load api and init
            odoosync.load_credentials(connection=args.connection)
            if not odoosync.init_api():
                raise Exception(f"ERROR: Could not initialize api - please check the connection credentials")
        args.func(odoosync, args)
        exit()
    else:
        print("you have to chose a command... invoke with '--help' to get some")
        exit()


if __name__ == "__main__":
    main()

