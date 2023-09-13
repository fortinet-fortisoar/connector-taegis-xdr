""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """
import requests
import time
from connectors.core.connector import get_logger, ConnectorError
from connectors.core.utils import update_connnector_config
from taegis_xdr_api_auth import TaegisXDRAuth
import base64, json
from constants import *

logger = get_logger("taegis-xdr")

server_url_dict = {"US-1": "https://api.ctpx.secureworks.com", "US-2": "https://api.delta.taegis.secureworks.com",
                   "US WEST": "https://api.foxtrot.taegis.secureworks.com",
                   "EU": "https://api.echo.taegis.secureworks.com"}


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

    def make_request(self, endpoint='', params=None, data=None, method='GET', headers=None, url=None, json_data=None):
        try:
            if url is None:
                url = self.server_url + endpoint
            method_headers = {'Authorization': self.access_token, 'Content-Type': 'application/json'}
            headers.update(method_headers)
            response = requests.request(method=method, url=url,
                                        headers=headers, data=data, json=json_data, params=params,
                                        verify=self.verify_ssl)

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
    data_query = {"query": get_alerts_query.format(cql_query=params.get('cql_query'), limit=params.get('limit'),
                                                   offset=params.get('offset'))}
    return tx.make_request(method="POST", data=data_query)


def get_assets(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": get_assets_query.format(offset=params.get('offset'), limit=params.get('limit'),
                                         order_by=valid_dict.get(params.get('order_by')),
                                         order_direction=valid_dict.get(params.get('order_direction')),
                                         filter_asset_state=params.get('filter_asset_state'),
                                         only_most_recent=params.get('only_most_recent'))}
    return tx.make_request(method="POST", data=data_query)


def get_endpoint(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": get_endpoint_query.format(id= params.get('id'))}
    return tx.make_request(method="POST", data=data_query)


def get_investigations(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": get_investigations_query.format(page=params.get('page'),per_page=params.get('per_page'),query=params.get('query'),order_by_field=valid_dict.get(params.get('order_by_field')),order_by_direction=valid_dict.get(params.get('order_by_direction')))}
    return tx.make_request(method="POST", data=data_query)


def get_investigations_alerts(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": get_investigations_alerts_query.format(page=params.get('page'),per_page=params.get('per_page'),investigation_id=params.get('investigation_id'))}
    return tx.make_request(method="POST", data=data_query)


def get_playbook_execution(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": get_playbook_execution_query.format(playbookExecutionId=params.get('playbookExecutionId'))}
    return tx.make_request(method="POST", data=data_query)


def get_user_by_id(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {"query": get_user_by_id_query.format(user_id=params.get('user_id'))}
    return tx.make_request(method="POST", data=data_query, headers={"x-tenant-context": params.get('tenant_id')})


def isolate_assets(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": isolate_assets_query.format(id=params.get('id'),reason=params.get('reason'))}
    return tx.make_request(method="POST", data=data_query)


def update_alert_status(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {"query": update_alert_status_query.format(alert_ids=params.get('alert_ids'),resolution_status=valid_dict.get(params.get('resolution_status')), reason=params.get('reason'))}
    return tx.make_request(method="POST", data=data_query)


def update_investigation(config: dict, params: dict):
    params = _build_payload(params)
    tx = TaegisXDR(config)
    data_query = {
        "query": update_investigation_query.format(investigation_id=params.get('investigation_id'),description=params.get('description'),key_findings=params.get('key_findings'),priority=params.get('priority'), status={params.get('status')}, asignee_id=params.get('asignee_id'))}
    return tx.make_request(method="POST", data=data_query)


def _build_payload(params):
    return {key: val for key, val in params.items() if val is not None and val != ''}


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
    "update_investigation": update_investigation
}
