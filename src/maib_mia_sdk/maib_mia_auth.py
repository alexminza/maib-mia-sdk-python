"""Python SDK for maib MIA API"""

from .maib_mia_sdk import MaibMiaSdk, MaibMiaTokenException


class MaibMiaAuthRequest:
    """Factory class responsible for creating new instances of the MaibMiaAuth class."""

    @staticmethod
    def create(base_url: str = MaibMiaSdk.DEFAULT_BASE_URL):
        """Creates an instance of the MaibMiaAuth class."""

        client = MaibMiaSdk(base_url=base_url)
        return MaibMiaAuth(client)

class MaibMiaAuth:
    _client: MaibMiaSdk = None

    def __init__(self, client: MaibMiaSdk):
        self._client = client

    #region Generate token API
    def generate_token(self, client_id: str, client_secret: str):
        """Obtain Authentication Token

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/authentication/obtain-authentication-token"""

        token_data = self._build_generate_data(
            client_id=client_id,
            client_secret=client_secret)

        try:
            method = 'POST'
            endpoint = MaibMiaSdk.AUTH_TOKEN
            response = self._client.send_request(method=method, url=endpoint, data=token_data)
        except Exception as ex:
            raise MaibMiaTokenException(f'HTTP error while sending {method} request to endpoint {endpoint}: {ex}') from ex

        result = self._client.handle_response(response, MaibMiaSdk.AUTH_TOKEN)
        return result

    async def generate_token_async(self, client_id: str, client_secret: str):
        """Obtain Authentication Token

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/authentication/obtain-authentication-token"""

        token_data = self._build_generate_data(
            client_id=client_id,
            client_secret=client_secret)

        try:
            method = 'POST'
            endpoint = MaibMiaSdk.AUTH_TOKEN
            response = await self._client.send_request_async(method=method, url=endpoint, data=token_data)
        except Exception as ex:
            raise MaibMiaTokenException(f'HTTP error while sending {method} request to endpoint {endpoint}: {ex}') from ex

        result = self._client.handle_response(response, MaibMiaSdk.AUTH_TOKEN)
        return result

    @classmethod
    def _build_generate_data(cls, client_id: str, client_secret: str):
        if not client_id and not client_secret:
            raise MaibMiaTokenException('Client ID and Client Secret are required.')

        token_data = {
            'clientId': client_id,
            'clientSecret': client_secret
        }

        return token_data
    #endregion
