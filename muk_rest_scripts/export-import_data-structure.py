import json
import sys
import argparse
import time
from datetime import datetime, timezone, timedelta
import random
from pprint import pprint
import requests
from requests_oauthlib import OAuth2Session
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from oauthlib.oauth2 import BackendApplicationClient
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
        self.verbosity = verbosity
        self.readonly = readonly

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
            self.token = self.oauth.fetch_token(
                token_url=self.route(self.token_url),
                client_id=self.client_id, client_secret=self.client_secret
            )
            if self.verbosity > 2:
                print(f"got token {self.token}")
        return

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
        if not self.access_token or self.token_expiration_date - timedelta(seconds=10) <= fields.Datetime.now():
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
        except Error as e:
            raise # re-raise all other exceptions
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
        if self.verbosity > 1:
            print('json data:')
            print(json.dumps(data, indent=2))
        if self.auth_type == "oauth2":
            response = self._exec_oauth(self.route(endpoint), type=type, data=data)
        else:
            response = self._exec_other(self.route(endpoint), type=type, data=data, json_data=json_data)
        if not response:
            return response
        if response.status_code != 200:
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
            return False
        else:
            if self.verbosity > 2:
                print("Response:")
                print(json.dumps(response.json(), indent=2))
            return response.json()



class DataStructureSync:
    """This class can read a data structure including recursingly the generate or parse structures from Odoo 
    and save it as a json file or read a json file and create a new data structure including recusrively
    their generator and parser structures"""
    def __init__(self, verbosity=0, readonly=False, cred_file_name="default_credentials.json", 
                    data_file_name="exported_data_structure.json", structure_name='Example Data Structure'):
        # object data
        self.odoo_api = None # this will hold the connection to Odoo after the api init
        self.cred_file_name = cred_file_name
        self.data_file_name = data_file_name
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

        # format defaults
        self.dt_format_odoo = '%Y-%m-%d %H:%M:%S'
        self.dt_format_data = '%Y-%m-%dT%H:%M:%S.%fZ'

        # lists of fields to be processed
        # data.structure fields
        self.data_structure_fields_simple = [
            'field_name',
            'is_execute_for_each_record',
            'is_for_specific_records',
            'model_name',
            'name',
            'records_domain',
            'structure_type',
            'value_type',
        ]
        self.data_structure_fields_o2m = [
            'generator_ids',
            'parser_ids',
        ]
        self.data_structure_fields_m2o = [
            'child_id',
            'model_id',
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
            'model_name',
            'parent_id',
            'records_domain',
            'sequence',
            'skip_if_value',
            'structure_value_type',
            'translation_for',
            'value',
            'value_type',
            'value_type_cast',
        ]
        self.generator_structure_fields_o2m = [
            'child_ids',
            'lang_mapping_ids',
        ]
        self.generator_structure_fields_m2o = [
            'lang_id',
            'model_id',
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
            'structure_id',
        ]
        # language.mappping fields
        self.language_mapping_fields_simple = [
            'keyword',
        ]
        self.language_mapping_fields_o2m = [
        ]
        self.language_mapping_fields_m2o = [
            'lang_id',
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
            'generator_id',
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
            'parent_id',
            'structure_id',
        ]


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
            raise Exception("ERROR: could not find connection {} in credentials file {}".format(connection, cred_file))
        return True


    def write_scaffold_credentials(self, cred_file_name='example_credentials.json', connection='example_connection'):
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


    def init_api(self):
        # init API
        if self.verbosity > 0:
            print("INFO: Initialize API and authenticate")
        self.odoo_api = RestAPI(auth_type=self.auth_type, headers={}, client_id=self.client_id, 
                        client_secret=self.client_secret, base_url=self.base_url, 
                        token_url=self.token_url, verbosity=self.verbosity, readonly=self.readonly)
        #self.odoo_api._get_access_token() # this is just for testing different libraries
        self.odoo_api.authenticate()

        # test API
        if self.verbosity > 1:
            pprint(self.odoo_api.execute(''))
            pprint(self.odoo_api.execute('/user'))


    def export_structure(self, data_structure_name=None, data_file_name=None,
                            export_meta=False, export_no_import=False):
        # building the list of fields to be exported depending on args
        data_structure_fields_export = self.data_structure_fields_simple + \
            self.data_structure_fields_o2m + self.data_structure_fields_m2o + \
            (self.data_structure_fields_meta if export_meta else []) + \
            (self.data_structure_fields_no_import if export_no_import else [])
        generator_structure_fields_export = self.generator_structure_fields_simple + \
            self.generator_structure_fields_o2m + self.generator_structure_fields_m2o + \
            (self.generator_structure_fields_meta if export_meta else []) + \
            (self.generator_structure_fields_no_import if export_no_import else [])
        parser_structure_fields_export = self.parser_structure_fields_simple + \
            self.parser_structure_fields_o2m + self.parser_structure_fields_m2m + \
            self.parser_structure_fields_m2o + \
            (self.parser_structure_fields_meta if export_meta else []) + \
            (self.parser_structure_fields_no_import if export_no_import else [])
        language_mapping_fields_export = self.language_mapping_fields_simple + \
            self.language_mapping_fields_o2m + self.language_mapping_fields_m2o + \
            (self.language_mapping_fields_meta if export_meta else []) + \
            (self.language_mapping_fields_no_import if export_no_import else [])

        # get main data structure
        data_structure = {}
        if self.verbosity > 1:
            print(f"looking for and exporting the data.structure named {data_structure_name}")
        data = {
            'model': "data.structure",
            'domain': json.dumps([['name', '=', data_structure_name]]),
            'fields': json.dumps(data_structure_fields_export),
            'limit': 1
        }
        if self.verbosity >= 2:
            pprint(data)
        response = self.odoo_api.execute('search_read', type="GET", data=data)
        if self.verbosity >= 1:
            print("Response:")
            pprint(response)
        if response:
            data_structure_data = next(iter(response))
            data_structure = {'data_structure': data_structure_data}

            # get all generator structures
            generator_structures = {}
            for generator_id in data_structure_data.get('generator_ids'):
                generator_structures.update(self.read_generator_structure(generator_id = generator_id, 
                            fields = generator_structure_fields_export))
            data_structure['generator_structures'] = generator_structures

            # get all language mappings on the generators
            language_mappings = {}
            for generator_id in generator_structures:
                mapping_ids = generator_structures[generator_id]['lang_mapping_ids']
                print(f"checking generator {generator_id} for languge mappings and found {mapping_ids}")
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
            if self.verbosity >= 1:
                print('INFO: did not get any response, finishing')

        # write json
        print("got the following data in the end")
        pprint(data_structure)
        with open(data_file_name, 'w') as data_structure_file:
            json.dump(data_structure, data_structure_file, indent=2)
        print(f"INFO: the data structure {data_structure_name} has been read and written to the file {data_file_name}")


    def read_generator_structure(self, generator_id=None, fields=[]):
        generator_structures = {}
        if self.verbosity > 2:
            print(f"looking for and exporting the generate.data.structure with id {generator_id}")
        data = {
            'model': "generate.data.structure",
            'domain': json.dumps([['id', '=', generator_id]]),
            'fields': json.dumps(fields),
            'limit': 1
        }
        if self.verbosity >= 2:
            pprint(data)
        response = self.odoo_api.execute('search_read', type="GET", data=data)
        if self.verbosity >= 1:
            print("Response:")
            pprint(response)
        if response:
            generator_structure = next(iter(response))
            generator_structures = {generator_id: generator_structure}

            # get all sub generator structures
            for sub_generator_id in generator_structure.get('child_ids'):
                generator_structures.update(self.read_generator_structure(generator_id=sub_generator_id))

        return generator_structures


    def read_language_mappings(self, mapping_ids=[], fields=[]):
        language_mappings = {}
        if self.verbosity > 2:
            print(f"looking for and exporting the language.mapping with ids {mapping_ids}")
        if not mapping_ids:
            return {}
        data = {
            'model': "language.mapping",
            'domain': json.dumps([['id', '=', mapping_ids]]),
            'fields': json.dumps(fields),
        }
        if self.verbosity >= 2:
            pprint(data)
        response = self.odoo_api.execute('search_read', type="GET", data=data)
        if self.verbosity >= 1:
            print("Response:")
            pprint(response)
        if response:
            for language_mapping  in response:
                language_mappings.update({language_mapping.get('id'): language_mapping})

        return language_mappings


    def read_parser_structure(self, parser_id=None, fields=[]):
        parser_structures = {}
        if self.verbosity > 2:
            print(f"looking for and exporting the parse.data.structure with id {parser_id}")
        data = {
            'model': "parse.data.structure",
            'domain': json.dumps([['id', '=', parser_id]]),
            'fields': json.dumps(fields),
            'limit': 1
        }
        if self.verbosity >= 2:
            pprint(data)
        response = self.odoo_api.execute('search_read', type="GET", data=data)
        if self.verbosity >= 1:
            print("Response:")
            pprint(response)
        if response:
            parser_structure = next(iter(response))
            parser_structures = {parser_id: parser_structure}

            # get all sub parser structures
            for sub_parser_id in parser_structure.get('child_ids'):
                parser_structures.update(self.read_parser_structure(parser_id=sub_parser_id))

        return parser_structures


    def create_structure(self, data_structure_name=None, data_file_name=None):
        if not(data_structure_name):
            raise Exception("WARN: no data structure name given - will use the one found in the data")
        if not(data_file_name):
            data_file_name = self.data_file_name
        if not(data_file_name):
            raise Exception("ERROR: no data file given")

        # read credentials
        with open(data_file_name) as data_structure_file:    
            data_structure = json.load(data_structure_file)
            if not data_structure:
                raise Exception(f"ERROR: could not load data structure from file {data_file_name}. aborting.")
        if self.verbosity >= 1:
            print("Loaded data:")
            pprint(data_structure)
        if not 'data_structure' in data_structure:
            print(f"ERROR: could not find data_structure in data from {data_file_name}, aborting.")

        # now build the structure in a way it can be used to be sent to Odoo
        # for m2o fields we need to remove the list and use just the id
        # for o2m fields we need to create new records on the fly using the list of tuples
        #   o2m_filed_ids = [(0, 0, {'field1': 'value_A1', 'field2': 'value_A2'})
        #                   (0, 0, {'field1': 'value_B1', 'field2': 'value_B2'})]
        # the m2m field uses existing records, so we handle it like a list of m2o
        # also not used (meta) fields like id, create/write date/user will not be used

        # start with the simple fields
        data_structure_values = {k: v for k, v in data_structure['data_structure'].items() \
                                        if k in self.data_structure_fields_simple}
        # as the m2o fields are exported as a list of id and display_name if set at all, we only need the id
        data_structure_values.update({k: v[0] for k, v in data_structure['data_structure'].items() \
                                        if k in self.data_structure_fields_m2o and type(v) == list})
        # now for the o2m we have to recurse to fill the lists
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
        if data_structure_name:
            data_structure_values['name'] = data_structure_name

        # now create a new data structure in Odoo
        if self.verbosity >= 1:
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
            print("WARNING: there seems to have been a problem")


    def create_generator_tuple(self, generator_id=None, generator_structures={}, language_mappings={}):
        if self.verbosity >= 3:
            print(f"create_generator_tuple: build generator {generator_id} from {generator_structures.keys()}")
        if not generator_id or not generator_structures or not generator_id in generator_structures:
            print("create_generator_tuple: missing data")
            return []
        # start with the simple fields
        generator_structure = {k: v for k, v in generator_structures[generator_id].items() if k in self.generator_structure_fields_simple}
        # as the m2o fields are exported as a list of id and display_name if set at all, we only need the id
        generator_structure.update({k: v[0] for k, v in generator_structures[generator_id].items() if k in self.generator_structure_fields_m2o and type(v) == list})
        # now for the o2m first empty lists are added, to fill them next
        generator_structure.update({k: [] for k in self.generator_structure_fields_o2m})
        # for the language mapping o2m new records are added using the tuples
        for language_mapping in generator_structures[generator_id].get('lang_mapping_ids', []):
            generator_structure['lang_mapping_ids'] += [(0, 0, {
                            'keyword': language_mappings[str(language_mapping)]['keyword'],
                            'lang_id': language_mappings[str(language_mapping)]['lang_id'][0],
                            })]
        # for the o2m child_ids it needs recursing to fill the lists
        for child_id in generator_structures[generator_id].get('child_ids', []):
            generator_structure['child_ids'] += [(0, 0, self.create_generator_tuple(generator_id=str(child_id), 
                                generator_structures=generator_structures, 
                                language_mappings=language_mappings))]
        return generator_structure


    def create_parser_tuple(self, parser_id=None, parser_structures = {}):
        if self.verbosity >= 2:
            print(f"create_parser_tuple: build parser {parser_id} from {parser_structures.keys()}")
        if not parser_id or not parser_structures or not parser_id in parser_structures:
            print("create_parser_tuple: missing data")
            return []
        # start with the simple fields
        parser_structure = {k: v for k, v in parser_structures[parser_id].items() if k in self.parser_structure_fields_simple}
        # as the m2o fields are exported as a list of id and display_name if set at all, we only need the id
        parser_structure.update({k: v[0] for k, v in parser_structures[parser_id].items() if k in self.parser_structure_fields_m2o and type(v) == list})
        # now for the o2m first empty lists are added, to fill them next
        parser_structure.update({k: [] for k in self.parser_structure_fields_o2m})
        # for the o2m child_ids it needs recursing to fill the lists
        for child_id in parser_structures[parser_id].get('child_ids', []):
            parser_structure['child_ids'] += [(0, 0, self.create_parser_tuple(parser_id=str(child_id), 
                                parser_structures=parser_structures))]
        return parser_structure


    def update_structure(self, data_structure_name=None, data_file_name=None):
        print(f"WARNING: updating structures in Odoo isn't implemented yet")
        return False



#################
# main
#################


# functions for subparser
def export_structure(odoosync, args):
    #print("order update was chosen")
    odoosync.export_structure(data_structure_name=args.structure, data_file_name=args.data_file, 
                                export_meta=args.export_meta, export_no_import=args.export_no_import)

def create_structure(odoosync, args):
    #print("create was chosen")
    odoosync.create_structure(data_structure_name=args.structure, data_file_name=args.data_file)

def update_structure(odoosync, args):
    #print("update was chosen")
    print("WARNING: updating an existing data structure isn't implemented yet")
    return False
    odoosync.update_structure(data_structure_name=args.structure, data_file_name=args.data_file)

def scaffold_credentials(odoosync, args):
    #print("WARNING: export example credentials to example_credentials.json is not implemented yet ;)")
    odoosync.write_scaffold_credentials(cred_file_name='example_credentials.json')
    exit()


# parser for the command line input
def main():
    parser = argparse.ArgumentParser(description="Export / Import tool to read a data generator from Odoo "
                        "recursively and save it as a json file - or to read a json file and create a data "
                        "structure in Odoo recursively.")

    # main / common parser elements
    parser.add_argument("-r", "--read-only", action="store_true", 
                        help="do not send / update data to Odoo, just simulate, data can be read.")
    parser.add_argument("-c", "--credentials-file", action="store", default='default_credentials.json',
                        help="specify the json file to read credentials from, defaults to default_credentials.json")
    parser.add_argument("-d", "--data-file", action="store", default='default_data_structure.json',
                        help="specify the json file to read or write the data structure to / from, defaults to "
                        "default_data_structure.json")
    parser.add_argument("-v", "--verbosity", action="count", default=0,
                        help="increase verbosity to show the successful steps (v), more details (vv), "
                             "even more details (vvv), everything (vvvv)")

    # add subparsers for individual functions: scaffold, export, create, update
    subparsers = parser.add_subparsers(title="command",
                        description="what the script should do",
                        help="the main command to define if a data structure should be exported from Odoo or "
                            "if a new data structure should be created in Odoo or to scaffold a creentials file. "
                            "use 'connection command --help' for command specific arguments")

    # arguments to export a data structure from Odoo and save it to the local json file
    parser_export = subparsers.add_parser('export', help="this will search for a data structure identified by it's "
                            "name and will read it recursively and store it in a json file")
    parser_export.add_argument("connection", help="the name of a connection to be used; the detailed connection "
                        "parameters must be stored in a file containing the connection details and credentials "
                        "as a dictionary stored in a json format. use --credentials-file to use a specific file, "
                        "otherwise a default file named default_credentials.json will be used. Use the command "
                        "scaffold to output an example credentials file to example_credentials.json.")
    parser_export.add_argument("structure", help="the name of the data structure to be exported from Odoo.")
    parser_export.add_argument("-m", "--export-meta", action="store_true",  default=False,
                        help="also export meta data")
    parser_export.add_argument("-n", "--export-no-import", action="store_true",  default=False,
                        help="also export non-importable fields")
    parser_export.set_defaults(func=export_structure, init_api=True)

    # arguments to create a data structure in Odoo using data from the local json file
    parser_create = subparsers.add_parser('create', help="this will read the data from the local json file "
                            "and create a new data structure in Odoo recursively")
    parser_create.add_argument("connection", help="the name of a connection to be used; the detailed connection "
                        "parameters must be stored in a file containing the connection details and credentials "
                        "as a dictionary stored in a json format. use --credentials-file to use a specific file, "
                        "otherwise a default file named default_credentials.json will be used. Use the command "
                        "scaffold to output an example credentials file to example_credentials.json.")
    parser_create.add_argument("structure", help="the name of the data structure to be created in Odoo.")
    parser_create.set_defaults(func=create_structure, init_api=True)

    # arguments to update a data structure in Odoo using data from the local json file
    parser_update = subparsers.add_parser('update', help="this will read the data from the local json file "
                            "and update an existing data structure in Odoo recursively")
    parser_update.add_argument("connection", help="the name of a connection to be used; the detailed connection "
                        "parameters must be stored in a file containing the connection details and credentials "
                        "as a dictionary stored in a json format. use --credentials-file to use a specific file, "
                        "otherwise a default file named default_credentials.json will be used. Use the command "
                        "scaffold to output an example credentials file to example_credentials.json.")
    parser_update.add_argument("structure", help="the name of the data structure to be updated in Odoo.")
    parser_update.set_defaults(func=update_structure, init_api=True)

    # scaffold a new example credentials file
    parser_scaffold = subparsers.add_parser('scaffold', help="export an example credentials file to "
                        "example_credentials.json")
    parser_scaffold.set_defaults(func=scaffold_credentials, init_api=False)


    # parse the arguments
    args = parser.parse_args()

    if args.credentials_file and args.verbosity > 1:
        print(f"INFO: will use credentials file {args.credentials_file}")
    if args.data_file and args.verbosity > 1:
        print(f"INFO: will use data file {args.data_file}")


    # execute the requested command
    if 'func' in args:
        # init the sync object
        odoosync = DataStructureSync(cred_file_name=args.credentials_file or 'default_credentials.json', 
                        data_file_name=args.data_file or 'default_data_structure.json', 
                        verbosity=args.verbosity, readonly=args.read_only)
        if args.init_api:
            # load api and init
            odoosync.load_credentials(connection=args.connection)
            odoosync.init_api()
        args.func(odoosync, args)
        exit()
    else:
        print("you have to chose a command... invoke with '--help' to get some")
        exit()


if __name__ == "__main__":
    main()

