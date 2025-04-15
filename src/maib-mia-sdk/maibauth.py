"""Python SDK for maib MIA QR API"""

import logging
from maibmiasdk import MaibMiaSdk, MaibTokenException

class MaibAuthRequest:
    """Factory class responsible for creating new instances of the MaibAuth class."""

    @staticmethod
    def create(base_url: str = MaibMiaSdk.DEFAULT_BASE_URL):
        """Creates an instance of the MaibAuth class."""

        client = MaibMiaSdk(base_url=base_url)
        return MaibAuth(client)

class MaibAuth:
    __client: MaibMiaSdk = None

    def __init__(self, client: MaibMiaSdk):
        self.__client = client

    def generate_token(self, client_id: str, client_secret: str):
        """Generates a new access token using the given client ID and secret."""

        if not client_id and not client_secret:
            raise MaibTokenException('Client ID and Client Secret are required.')

        post_data = {
            'clientId': client_id,
            'clientSecret': client_secret
        }

        try:
            response = self.__client.send_request('POST', MaibMiaSdk.AUTH_TOKEN, post_data)
        except Exception as ex:
            logging.exception('MaibAuth.generate_token')
            raise MaibTokenException(f'HTTP error while sending POST request to endpoint {MaibMiaSdk.AUTH_TOKEN}') from ex

        result = self.__client.handle_response(response, MaibMiaSdk.AUTH_TOKEN)
        return result
