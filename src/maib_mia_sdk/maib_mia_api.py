"""Python SDK for maib MIA QR API"""

import logging
from .maib_mia_sdk import MaibMiaSdk, MaibPaymentException

logger = logging.getLogger(__name__)

class MaibMiaApiRequest:
    """Factory class responsible for creating new instances of the MaibMiaApi class."""

    @staticmethod
    def create(base_url: str = MaibMiaSdk.DEFAULT_BASE_URL):
        """Creates a new instance of MaibMiaApi."""

        client = MaibMiaSdk(base_url=base_url)
        return MaibMiaApi(client)

class MaibMiaApi:
    __client: MaibMiaSdk = None

    REQUIRED_QR_PARAMS = ['type', 'amountType', 'currency']
    REQUIRED_TEST_PAY_PARAMS = ['qrId', 'amount', 'iban', 'currency', 'payerName']

    def __init__(self, client: MaibMiaSdk):
        self.__client = client

    def qr_create(self, data: dict, token: str):
        """Create QR"""
        return self.__execute_operation(endpoint=MaibMiaSdk.MIA_QR, data=data, token=token, required_params=self.REQUIRED_QR_PARAMS)

    def qr_details(self, qr_id: str, token: str):
        """Get QR details by QR ID"""
        return self.__execute_entity_id_operation(endpoint=MaibMiaSdk.MIA_QR_ID, entity_id=qr_id, token=token)

    def qr_cancel(self, qr_id: str, data: dict, token: str):
        """Cancel active QR by QR ID"""
        return self.__execute_entity_id_operation(endpoint=MaibMiaSdk.MIA_QR_CANCEL, entity_id=qr_id, token=token, method='POST', data=data)

    def qr_list(self, params: dict, token: str):
        """Get QR list with filter"""
        return self.__execute_operation(endpoint=MaibMiaSdk.MIA_QR, data=None, token=token, required_params=None, method='GET', params=params)

    def test_pay(self, data: dict, token: str):
        """Simulation of test payment"""
        return self.__execute_operation(endpoint=MaibMiaSdk.MIA_TEST_PAY, data=data, token=token, required_params=self.REQUIRED_TEST_PAY_PARAMS)

    def payment_details(self, pay_id: str, token: str):
        """Get payment details by payment ID"""
        return self.__execute_entity_id_operation(endpoint=MaibMiaSdk.MIA_PAYMENTS_ID, entity_id=pay_id, token=token)

    def payment_refund(self, pay_id: str, data: dict, token: str):
        """Refund payment by payment ID"""
        return self.__execute_entity_id_operation(endpoint=MaibMiaSdk.MIA_PAYMENTS_REFUND, entity_id=pay_id, token=token, method='POST', data=data)

    def payment_list(self, params: dict, token: str):
        """Get payments list with filter"""
        return self.__execute_operation(endpoint=MaibMiaSdk.MIA_PAYMENTS, data=None, token=token, required_params=None, method='GET', params=params)

    def __execute_operation(self, endpoint: str, data: dict, token: str, required_params: list, method: str = 'POST', params: dict = None):
        try:
            self.__validate_params(data=data, required_params=required_params)
            self.__validate_access_token(token=token)
            return self.__send_request(method=method, endpoint=endpoint, data=data, params=params, token=token)
        except MaibPaymentException as ex:
            logger.exception('MaibMiaApi.__execute_operation')
            raise MaibPaymentException(f'Invalid request: {ex}') from ex

    def __execute_entity_id_operation(self, endpoint: str, entity_id: str, token: str, method: str = 'GET', data: dict = None, params: dict = None):
        try:
            self.__validate_id_param(entity_id=entity_id)
            self.__validate_access_token(token=token)
            return self.__send_request(method=method, endpoint=endpoint, token=token, data=data, params=params, entity_id=entity_id)
        except MaibPaymentException as ex:
            logger.exception('MaibMiaApi.__execute_entity_id_operation')
            raise MaibPaymentException(f'Invalid request: {ex}') from ex

    def __send_request(self, method: str, endpoint: str, token: str, data: dict = None, params: dict = None, entity_id: str = None):
        """Sends a request to the specified endpoint."""

        try:
            response = self.__client.send_request(method=method, url=endpoint, data=data, params=params, token=token, entity_id=entity_id)
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

        if data and required_params:
            # Check that all required parameters are present
            for param in required_params:
                if data.get(param) is None:
                    raise MaibPaymentException(f'Missing required parameter: {param}')

        return True
