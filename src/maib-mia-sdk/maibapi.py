"""Python SDK for maib MIA QR API"""

import logging
from maibmiasdk import MaibMiaSdk, MaibPaymentException

class MaibApiRequest:
    """Factory class responsible for creating new instances of the MaibApi class."""

    @staticmethod
    def create(base_url: str = MaibMiaSdk.DEFAULT_BASE_URL):
        """Creates a new instance of MaibApi."""

        client = MaibMiaSdk(base_url=base_url)
        return MaibApi(client)

class MaibApi:
    __client: MaibMiaSdk = None

    REQUIRED_QR_PARAMS = ['type', 'amountType', 'currency']
    REQUIRED_TEST_PAY_PARAMS = ['qrId', 'amount', 'iban', 'currency', 'payerName']

    def __init__(self, client: MaibMiaSdk):
        self.__client = client

    def create_qr(self, data: dict, token: str):
        """Sends a request to the create QR endpoint."""
        return self.__execute_operation(endpoint=MaibMiaSdk.MIA_QR, data=data, token=token, required_params=self.REQUIRED_QR_PARAMS)

    def test_pay(self, data: dict, token: str):
        """Sends a request to the test pay endpoint."""
        return self.__execute_operation(endpoint=MaibMiaSdk.MIA_TEST_PAY, data=data, token=token, required_params=self.REQUIRED_TEST_PAY_PARAMS)

    def payment_details(self, pay_id: str, token: str):
        """Sends a request to the pay-info endpoint."""
        return self.__execute_entity_id_operation(endpoint=MaibMiaSdk.MIA_PAYMENTS, entity_id=pay_id, token=token)

    def __execute_operation(self, endpoint: str, data: dict, token: str, required_params: list, method: str = 'POST'):
        try:
            self.__validate_params(data=data, required_params=required_params)
            self.__validate_access_token(token=token)
            return self.__send_request(method=method, endpoint=endpoint, data=data, token=token)
        except MaibPaymentException as ex:
            logging.exception('MaibApi.__execute_operation')
            raise MaibPaymentException(f'Invalid request: {ex}') from ex

    def __execute_entity_id_operation(self, endpoint: str, entity_id: str, token: str, method: str = 'GET'):
        try:
            self.__validate_id_param(entity_id=entity_id)
            self.__validate_access_token(token=token)
            return self.__send_request(method=method, endpoint=endpoint, token=token, entity_id=entity_id)
        except MaibPaymentException as ex:
            logging.exception('MaibApi.__execute_entity_id_operation')
            raise MaibPaymentException(f'Invalid request: {ex}') from ex

    def __send_request(self, method: str, endpoint: str, token: str, data: dict = None, entity_id: str = None):
        """Sends a request to the specified endpoint."""

        try:
            response = self.__client.send_request(method=method, url=endpoint, data=data, token=token, entity_id=entity_id)
        except Exception as ex:
            raise MaibPaymentException(f'HTTP error while sending {method} request to endpoint {endpoint}: {ex}') from ex

        return self.__client.handle_response(response, endpoint)

    @staticmethod
    def __validate_access_token(token: str):
        """Validates the access token."""

        if not token or len(token) == 0:
            raise MaibPaymentException('Access token is not valid. It should be a non-empty string.')

    @staticmethod
    def __validate_id_param(entity_id: str):
        """Validates the ID parameter."""

        if not entity_id:
            raise MaibPaymentException('Missing ID.')

        if len(entity_id) == 0:
            raise MaibPaymentException('Invalid ID parameter. Should be string of 36 characters.')

    @staticmethod
    def __validate_params(data: dict, required_params: list):
        """Validates the parameters."""

        # Check that all required parameters are present
        for param in required_params:
            if data.get(param) is None:
                raise MaibPaymentException(f'Missing required parameter: {param}')

        return True
