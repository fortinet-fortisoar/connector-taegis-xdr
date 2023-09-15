""" Copyright start
Copyright (C) 2008 - 2023 Fortinet Inc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end """
from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import operations
from .taegis_xdr_api_auth import check
logger = get_logger("taegis-xdr")

class TaegisXDRConnector(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            operation = operations.get(operation)
            if not operation:
                logger.error('Unsupported operation: {}'.format(operation))
                raise ConnectorError('Unsupported operation')
            return operation(config, params)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)

    def check_health(self, config=None):
        try:
            config['connector_info'] = {"connector_name": self._info_json.get('name'),
                "connector_version": self._info_json.get('version')}
            check(config)
        except Exception as err:
            raise ConnectorError(err)
