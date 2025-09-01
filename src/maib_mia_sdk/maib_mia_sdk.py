"""Python SDK for maib MIA API"""

import logging
import json
import hashlib
import hmac
import base64

import httpx

logger = logging.getLogger(__name__)


# Based on Python SDK for maib ecommerce API https://github.com/alexminza/maib-ecommerce-sdk-python (https://pypi.org/project/maib-ecommerce-sdk/)
# maib MIA QR API https://docs.maibmerchants.md/mia-qr-api

class MaibMiaSdk:
    # maib MIA QR API base urls
    DEFAULT_BASE_URL = 'https://api.maibmerchants.md/v2/'
    SANDBOX_BASE_URL = 'https://sandbox.maibmerchants.md/v2/'

    # maib MIA QR API endpoints
    AUTH_TOKEN = 'auth/token'

    MIA_QR = 'mia/qr'
    MIA_QR_HYBRID = 'mia/qr/hybrid'
    MIA_QR_ID = 'mia/qr/{id}'
    MIA_QR_EXTENSION = 'mia/qr/{id}/extension'
    MIA_QR_CANCEL = 'mia/qr/{id}/cancel'
    MIA_QR_EXTENSION_CANCEL = 'mia/qr/{id}/extension/cancel'
    MIA_PAYMENTS = 'mia/payments'
    MIA_PAYMENTS_ID = 'mia/payments/{id}'
    MIA_PAYMENTS_REFUND = 'mia/payments/{id}/refund'
    MIA_TEST_PAY = 'mia/test-pay'

    MIA_RTP = 'rtp'
    MIA_RTP_ID = 'rtp/{id}'
    MIA_RTP_CANCEL = 'rtp/{id}/cancel'
    MIA_RTP_REFUND = 'rtp/{id}/refund'
    MIA_RTP_TEST_ACCEPT = 'rtp/{id}/test-accept'
    MIA_RTP_TEST_REJECT = 'rtp/{id}/test-reject'

    DEFAULT_TIMEOUT = 30

    _base_url: str = None

    def __init__(self, base_url: str = DEFAULT_BASE_URL):
        self._base_url = base_url

    def _build_url(self, url: str, entity_id: str = None):
        """Build the complete URL for the request"""

        url = self._base_url + url

        if entity_id:
            url = url.format(id=entity_id)

        return url

    def _process_response(self, response: httpx.Response):
        if response.is_error:
            logger.error('%s Error: %d %s', self.__qualname__, response.status_code, response.text, extra={'method': response.request.method, 'url': response.request.url, 'params': response.request.url.params, 'response_text': response.text, 'status_code': response.status_code})
            #response.raise_for_status()

        response_json: dict = response.json()
        logger.debug('%s Response: %d', self.__qualname__, response.status_code, extra={'response_json': response_json})
        return response_json

    def send_request(self, method: str, url: str, data: dict = None, params: dict = None, token: str = None, entity_id: str = None):
        """Send a request and parse the response."""

        auth = BearerAuth(token) if token else None
        url = self._build_url(url=url, entity_id=entity_id)

        logger.debug('%s Request: %s %s', self.__qualname__, method, url, extra={'method': method, 'url': url, 'data': data, 'params': params, 'token': token})
        with httpx.Client() as client:
            response = client.request(method=method, url=url, params=params, json=data, auth=auth, timeout=self.DEFAULT_TIMEOUT)
            return self._process_response(response=response)

    async def send_request_async(self, method: str, url: str, data: dict = None, params: dict = None, token: str = None, entity_id: str = None):
        """Send async request and parse the response."""

        auth = BearerAuth(token) if token else None
        url = self._build_url(url=url, entity_id=entity_id)

        logger.debug('%s Request: %s %s', self.__qualname__, method, url, extra={'method': method, 'url': url, 'data': data, 'params': params, 'token': token})
        async with httpx.AsyncClient() as client:
            response = await client.request(method=method, url=url, params=params, json=data, auth=auth, timeout=self.DEFAULT_TIMEOUT)
            return self._process_response(response=response)

    @staticmethod
    def handle_response(response: dict, endpoint: str):
        """Handles errors returned by the API."""

        if not isinstance(response, dict):
            raise MaibMiaPaymentException(f"Invalid response received from server for endpoint {endpoint}")

        if response.get('ok') is True:
            response_result: dict = response.get('result')
            if response_result is not None:
                return response_result

            raise MaibMiaPaymentException(f'Invalid response received from server for endpoint {endpoint}: missing \'result\' field.')

        response_errors = response.get('errors')
        if isinstance(response_errors, list) and response_errors:
            error: dict = response_errors[0]
            raise MaibMiaPaymentException(f'Error sending request to endpoint {endpoint}: {error.get('errorMessage')} ({error.get('errorCode')})')

        raise MaibMiaPaymentException(f'Invalid response received from server for endpoint {endpoint}: missing \'ok\' and \'errors\' fields')

    @staticmethod
    def validate_callback_signature(callback_data: dict, signature_key: str):
        """Validates the callback data signature."""
        # https://docs.maibmerchants.md/mia-qr-api/en/notifications-on-callback-url
        # https://docs.maibmerchants.md/mia-qr-api/en/examples/signature-key-verification

        if not signature_key:
            raise MaibMiaPaymentException('Invalid signature key')

        callback_signature: str = callback_data.get('signature')
        callback_result: dict[str, any] = callback_data.get('result')

        if not callback_signature or not callback_result:
            raise MaibMiaPaymentException('Missing result or signature in callback data.')

        sorted_callback_result = sorted(((key.lower(), value) for key, value in callback_result.items()))
        filtered_callback_result = {
            key: (f'{float(value):.2f}' if isinstance(value, (int, float)) else str(value))
            for key, value in sorted_callback_result
            if value not in [None, '']
        }

        sign_callback_values = list(filtered_callback_result.values())
        sign_callback_values.append(signature_key)
        sign_string = ':'.join(sign_callback_values)
        calculated_signature = base64.b64encode(hashlib.sha256(sign_string.encode()).digest()).decode()

        return hmac.compare_digest(calculated_signature, callback_signature)

    @staticmethod
    def get_error_message(response: str):
        """Retrieves the error message from the API response."""

        error_message = ''
        if response:
            response_obj = json.loads(response)

            response_error = next(iter(response_obj.get('errors', [])), None)
            if response_error:
                error_message = response_error.get('errorMessage')
            else:
                error_message = 'Unknown error details.'

        return error_message

#region Auth
class BearerAuth(httpx.Auth):
    """Attaches HTTP Bearer Token Authentication to the given Request object."""
    # https://www.python-httpx.org/advanced/authentication/#custom-authentication-schemes

    token: str = None

    def __init__(self, token: str):
        self.token = token

    def auth_flow(self, request: httpx.Request):
        request.headers['Authorization'] = f'Bearer {self.token}'
        yield request
#endregion

#region Exceptions
class MaibMiaTokenException(Exception):
    pass

class MaibMiaPaymentException(Exception):
    pass
#endregion
