"""Python SDK for maib MIA QR API"""

import logging
from .maib_mia_sdk import MaibMiaSdk, MaibTokenException

logger = logging.getLogger(__name__)

class MaibMiaAuthRequest:
    """Factory class responsible for creating new instances of the MaibMiaAuth class."""

    @staticmethod
    def create(base_url: str = MaibMiaSdk.DEFAULT_BASE_URL):
        """Creates an instance of the MaibMiaAuth class."""

        client = MaibMiaSdk(base_url=base_url)
        return MaibMiaAuth(client)

class MaibMiaAuth:
    __client: MaibMiaSdk = None

    def __init__(self, client: MaibMiaSdk):
        self.__client = client

    def generate_token(self, client_id: str, client_secret: str):
        """Get Authentication Token"""

        if not client_id and not client_secret:
            raise MaibTokenException('Client ID and Client Secret are required.')

        post_data = {
            'clientId': client_id,
            'clientSecret': client_secret
        }

        try:
            response = self.__client.send_request('POST', MaibMiaSdk.AUTH_TOKEN, post_data)
        except Exception as ex:
            logger.exception('MaibMiaAuth.generate_token')
            raise MaibTokenException(f'HTTP error while sending POST request to endpoint {MaibMiaSdk.AUTH_TOKEN}') from ex

        result = self.__client.handle_response(response, MaibMiaSdk.AUTH_TOKEN)
        return result
