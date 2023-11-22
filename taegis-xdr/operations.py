"""
Copyright start
MIT License
Copyright (c) 2023 Fortinet Inc
Copyright end
"""
import requests
import time
from connectors.core.connector import get_logger, ConnectorError
from connectors.core.utils import update_connnector_config
from .taegis_xdr_api_auth import TaegisXDRAuth
import base64, json
from .constants import *

logger = get_logger("taegis-xdr")


class TaegisXDR:
    def __init__(self, config):
        self.server_url = server_url_dict.get(config.get('environment'))
        if not self.server_url.startswith('http') or not self.server_url.startswith('https'):
            self.server_url = 'https://' + self.server_url
        self.verify_ssl = config.get("verify_ssl", True)
        self.client_secret = config['client_secret']
        self.client_id = config['client_id']
        self.environment = config['environment']
        self.auth = TaegisXDRAuth(config)
        self.connector_info = config.pop('connector_info', '')
        self.access_token = self.auth.validate_token(config, self.connector_info)

    def make_request(self, headers=None, endpoint='', params=None, data=None, method='GET', url=None, json_data=None):
        try:
            if url is None:
                url = self.server_url + endpoint
            method_headers = {'Authorization': self.access_token, 'Content-Type': 'application/json'}
            if headers is None:
                headers = {}
            headers.update(method_headers)
            response = requests.request(method=method, url=url,
                                        headers=headers, data=data, json=json_data, params=params,
                                        verify=self.verify_ssl)

            try:
                from connectors.debug_utils.curl_script import make_curl
                make_curl(method, endpoint, headers=headers, params=params, data=data, verify_ssl=self.verify_ssl)
            except Exception as err:
                logger.error(f"Error in curl utils: {str(err)}")

            if response.ok:
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response.text
            else:
                logger.error("Error: {0}".format(response.json()))
                raise ConnectorError('{0}'.format(response.text))
        except requests.exceptions.SSLError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format('ssl_error'))
        except requests.exceptions.ConnectionError as e:
            logger.exception('{0}'.format(e))
            raise ConnectorError('{0}'.format('time_out'))
        except Exception as e:
            logger.error('{0}'.format(e))
            raise ConnectorError('{0}'.format(e))


def get_alerts(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {"query": get_alerts_query, "variables": {"in": params}}
    return tx.make_request(endpoint="/graphql", method="POST", data=json.dumps(data_query))


def get_assets(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {"query": get_assets_query,
                  "variables": params}
    return tx.make_request(endpoint="/graphql", method="POST", data=json.dumps(data_query))


def get_endpoint(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": get_endpoint_query, "variables": params}
    return tx.make_request(endpoint="/graphql", method="POST", data=json.dumps(data_query))


def get_investigations(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": get_investigations_query, "variables": params}
    return tx.make_request(endpoint="/graphql", method="POST", data=json.dumps(data_query))


def get_investigations_alerts(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": get_investigations_alerts_query, "variables": params}
    return tx.make_request(endpoint="/graphql", method="POST", data=json.dumps(data_query))


def get_playbook_execution(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": get_playbook_execution_query, "variables": params}
    return tx.make_request(endpoint="/graphql", method="POST", data=json.dumps(data_query))


def get_user_by_id(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {"query": get_user_by_id_query, "variables": params}
    return tx.make_request(endpoint="/graphql", method="POST", data=json.dumps(data_query),
                           headers={"x-tenant-context": params.get('tenant_id')})


def isolate_assets(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {"query": isolate_assets_query, "variables": params}
    return tx.make_request(endpoint="/graphql", method="POST", data=json.dumps(data_query))


def update_alert_status(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {"query": update_alert_status_query, "variables": {"in": params}}
    return tx.make_request(endpoint="/graphql", method="POST", data=json.dumps(data_query))


def update_investigation(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": update_investigation_query,
        "variables": {"investigation_id": params.pop('investigation_id'), "investigation": params}}
    return tx.make_request(endpoint="/graphql", method="POST", data=json.dumps(data_query))


def unarchive_investigation(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": unarchive_investigation_query,
        "variables": params}
    return tx.make_request(endpoint="/graphql", method="POST", data=json.dumps(data_query))


def add_alerts_to_investigation(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": add_alerts_to_investigation_query,
        "variables": params}
    return tx.make_request(endpoint="/graphql", method="POST", data=json.dumps(data_query))


def add_events_to_investigation(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": add_events_to_investigation_query,
        "variables": params}
    return tx.make_request(endpoint="/graphql", method="POST", data=json.dumps(data_query))


def create_investigation(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": create_investigation_query,
        "variables": {"investigation": params}}
    return tx.make_request(endpoint="/graphql", method="POST", data=json.dumps(data_query))


def execute_playbook(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": execute_playbook_query,
        "variables": params}
    return tx.make_request(endpoint="/graphql", method="POST", data=json.dumps(data_query))


def create_comment(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": create_comment_query,
        "variables": {"investigation_id": params.pop('investigation_id'), "activityLog": params}}
    return tx.make_request(endpoint="/graphql", method="POST", data=json.dumps(data_query))


def _build_payload(params):
    return {key: valid_dict.get(val, val) for key, val in params.items() if val is not None and val != ''}


operations = {
    "get_alerts": get_alerts,
    "get_assets": get_assets,
    "get_endpoint": get_endpoint,
    "get_investigations": get_investigations,
    "get_investigations_alerts": get_investigations_alerts,
    "get_playbook_execution": get_playbook_execution,
    "get_user_by_id": get_user_by_id,
    "isolate_assets": isolate_assets,
    "update_alert_status": update_alert_status,
    "update_investigation": update_investigation,
    "unarchive_investigation": unarchive_investigation,
    "add_alerts_to_investigation": add_alerts_to_investigation,
    "add_events_to_investigation": add_events_to_investigation,
    "create_investigation": create_investigation,
    "execute_playbook": execute_playbook,
    "create_comment": create_comment
}
