""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from requests import request
from time import time, ctime
from datetime import datetime
from connectors.core.connector import get_logger, ConnectorError
from connectors.core.utils import update_connnector_config
import json, base64, requests
from .constants import server_url_dict

logger = get_logger('taegis-xdr')


class TaegisXDRAuth:

    def __init__(self, config):
        self.server_url = server_url_dict.get(config.get('environment'))
        if not self.server_url.startswith('http') or not self.server_url.startswith('https'):
            self.server_url = 'https://' + self.server_url
        self.verify_ssl = config.get("verify_ssl", True)
        self.client_secret = config['client_secret']
        self.client_id = config['client_id']
        self.environment = config['environment']

    def generate_token(self, config):
        credentials = f"{self.client_id}:{self.client_secret}"
        credentials_base64 = base64.b64encode(credentials.encode()).decode()
        url = f"{server_url_dict.get(config.get('environment'))}/auth/api/v2/auth/token"
        payload = json.dumps({
            "grant_type": "client_credentials"
        })
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Basic {credentials_base64}'
        }
        response = requests.request("POST", url, headers=headers, data=payload)
        if response.ok:
            return response.json()

        raise ConnectorError("Wrong Credentials")

    def convert_ts_epoch(self, ts):
        datetime_object = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
        return datetime_object.timestamp()

    def validate_token(self, connector_config, connector_info):
        ts_now = time()
        if not connector_config.get('access_token'):
            token_resp = self.generate_token(connector_config)
            connector_config['access_token'] = token_resp['access_token']
            connector_config['expiry'] = token_resp['expiry']
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                     connector_config,
                                     connector_config['config_id'])

        expires = connector_config['expiry']
        expires_ts = self.convert_ts_epoch(expires)
        if ts_now > float(expires_ts):
            logger.info("Token expired at {0}".format(expires))
            token_resp = self.generate_token(connector_config)
            connector_config['access_token'] = token_resp['access_token']
            connector_config['expiry'] = token_resp['expiry']
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                     connector_config,
                                     connector_config['config_id'])

            return "Bearer {0}".format(connector_config.get('access_token'))
        else:
            return "Bearer {0}".format(connector_config.get('access_token'))


def check(config):
    try:
        txa = TaegisXDRAuth(config)
        token_resp = txa.generate_token(config)
        config['access_token'] = token_resp.get('access_token')
        config['expiry'] = token_resp.get('expiry')
        update_connnector_config(config['connector_info']['connector_name'],
                                 config['connector_info']['connector_version'], config,
                                 config['config_id'])
    except Exception as err:
        raise ConnectorError(str(err))
