"""Python SDK for maib MIA API"""

from .maib_mia_sdk import MaibMiaSdk, MaibMiaPaymentException


class MaibMiaApiRequest:
    """Factory class responsible for creating new instances of the MaibMiaApi class."""

    @staticmethod
    def create(base_url: str = MaibMiaSdk.DEFAULT_BASE_URL):
        """Creates a new instance of MaibMiaApi."""

        client = MaibMiaSdk(base_url=base_url)
        return MaibMiaApi(client)

class MaibMiaApi:
    _client: MaibMiaSdk = None

    # https://docs.maibmerchants.md/mia-qr-api/en/endpoints/payment-initiation/create-qr-code-static-dynamic#request-parameters-body
    REQUIRED_QR_PARAMS = ['type', 'amountType', 'currency', 'description']
    # https://docs.maibmerchants.md/mia-qr-api/en/endpoints/payment-initiation/create-hybrid-qr-code#request-body-parameters
    REQUIRED_QR_HYBRID_PARAMS = ['amountType', 'currency']
    # https://docs.maibmerchants.md/mia-qr-api/en/endpoints/payment-initiation/create-hybrid-qr-code/create-extension-for-qr-code-by-id#request-parameters-body
    REQUIRED_QR_EXTENSION_PARAMS = ['expiresAt', 'description']
    # https://docs.maibmerchants.md/mia-qr-api/en/payment-simulation-sandbox#request-parameters-body-json
    REQUIRED_TEST_PAY_PARAMS = ['qrId', 'amount', 'iban', 'currency', 'payerName']
    REQUIRED_RTP_PARAMS = ['alias', 'amount', 'currency', 'expiresAt', 'description']
    REQUIRED_TEST_ACCEPT_PARAMS = ['amount', 'currency']

    def __init__(self, client: MaibMiaSdk):
        self._client = client

    #region QR
    def qr_create(self, data: dict, token: str):
        """Create QR Code (Static, Dynamic)

        * https://docs.maibmerchants.md/mia-qr-api/en/overview/mia-qr-types
        * https://docs.maibmerchants.md/mia-qr-api/en/endpoints/payment-initiation/create-qr-code-static-dynamic"""

        return self._execute_operation(endpoint=MaibMiaSdk.MIA_QR, data=data, token=token, required_params=self.REQUIRED_QR_PARAMS)

    async def qr_create_async(self, data: dict, token: str):
        """Create QR Code (Static, Dynamic)

        * https://docs.maibmerchants.md/mia-qr-api/en/overview/mia-qr-types
        * https://docs.maibmerchants.md/mia-qr-api/en/endpoints/payment-initiation/create-qr-code-static-dynamic"""

        return await self._execute_operation_async(endpoint=MaibMiaSdk.MIA_QR, data=data, token=token, required_params=self.REQUIRED_QR_PARAMS)

    def qr_create_hybrid(self, data: dict, token: str):
        """Create Hybrid QR Code

        * https://docs.maibmerchants.md/mia-qr-api/en/overview/mia-qr-types
        * https://docs.maibmerchants.md/mia-qr-api/en/endpoints/payment-initiation/create-hybrid-qr-code"""

        return self._execute_operation(endpoint=MaibMiaSdk.MIA_QR_HYBRID, data=data, token=token, required_params=self.REQUIRED_QR_HYBRID_PARAMS)

    async def qr_create_hybrid_async(self, data: dict, token: str):
        """Create Hybrid QR Code

        * https://docs.maibmerchants.md/mia-qr-api/en/overview/mia-qr-types
        * https://docs.maibmerchants.md/mia-qr-api/en/endpoints/payment-initiation/create-hybrid-qr-code"""

        return await self._execute_operation_async(endpoint=MaibMiaSdk.MIA_QR_HYBRID, data=data, token=token, required_params=self.REQUIRED_QR_HYBRID_PARAMS)

    def qr_create_extension(self, qr_id: str, data: dict, token: str):
        """Create Extension for QR Code by ID

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/payment-initiation/create-hybrid-qr-code/create-extension-for-qr-code-by-id"""

        return self._execute_entity_id_operation(endpoint=MaibMiaSdk.MIA_QR_EXTENSION, entity_id=qr_id, token=token, method='POST', data=data)

    async def qr_create_extension_async(self, qr_id: str, data: dict, token: str):
        """Create Extension for QR Code by ID

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/payment-initiation/create-hybrid-qr-code/create-extension-for-qr-code-by-id"""

        return await self._execute_entity_id_operation_async(endpoint=MaibMiaSdk.MIA_QR_EXTENSION, entity_id=qr_id, token=token, method='POST', data=data)

    def qr_details(self, qr_id: str, token: str):
        """Retrieve QR Details by ID

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/information-retrieval-get/retrieve-qr-details-by-id"""

        return self._execute_entity_id_operation(endpoint=MaibMiaSdk.MIA_QR_ID, entity_id=qr_id, token=token)

    async def qr_details_async(self, qr_id: str, token: str):
        """Retrieve QR Details by ID

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/information-retrieval-get/retrieve-qr-details-by-id"""

        return await self._execute_entity_id_operation_async(endpoint=MaibMiaSdk.MIA_QR_ID, entity_id=qr_id, token=token)

    def qr_cancel(self, qr_id: str, data: dict, token: str):
        """Cancel Active QR (Static, Dynamic)

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/payment-cancellation/cancel-active-qr-static-dynamic"""

        return self._execute_entity_id_operation(endpoint=MaibMiaSdk.MIA_QR_CANCEL, entity_id=qr_id, token=token, method='POST', data=data)

    async def qr_cancel_async(self, qr_id: str, data: dict, token: str):
        """Cancel Active QR (Static, Dynamic)

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/payment-cancellation/cancel-active-qr-static-dynamic"""

        return await self._execute_entity_id_operation_async(endpoint=MaibMiaSdk.MIA_QR_CANCEL, entity_id=qr_id, token=token, method='POST', data=data)

    def qr_cancel_extension(self, qr_id: str, data: dict, token: str):
        """Cancel Active QR Extension (Hybrid)

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/payment-cancellation/cancel-active-qr-extension-hybrid"""

        return self._execute_entity_id_operation(endpoint=MaibMiaSdk.MIA_QR_EXTENSION_CANCEL, entity_id=qr_id, token=token, method='POST', data=data)

    async def qr_cancel_extension_async(self, qr_id: str, data: dict, token: str):
        """Cancel Active QR Extension (Hybrid)

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/payment-cancellation/cancel-active-qr-extension-hybrid"""

        return await self._execute_entity_id_operation_async(endpoint=MaibMiaSdk.MIA_QR_EXTENSION_CANCEL, entity_id=qr_id, token=token, method='POST', data=data)

    def qr_list(self, params: dict, token: str):
        """Retrieve List of QR Codes with Filtering Options

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/information-retrieval-get/display-list-of-qr-codes-with-filtering-options"""

        return self._execute_operation(endpoint=MaibMiaSdk.MIA_QR, data=None, token=token, required_params=None, method='GET', params=params)

    async def qr_list_async(self, params: dict, token: str):
        """Retrieve List of QR Codes with Filtering Options

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/information-retrieval-get/display-list-of-qr-codes-with-filtering-options"""

        return await self._execute_operation_async(endpoint=MaibMiaSdk.MIA_QR, data=None, token=token, required_params=None, method='GET', params=params)
    #endregion

    #region Payment
    def test_pay(self, data: dict, token: str):
        """Payment Simulation (Sandbox)

        https://docs.maibmerchants.md/mia-qr-api/en/payment-simulation-sandbox"""

        return self._execute_operation(endpoint=MaibMiaSdk.MIA_TEST_PAY, data=data, token=token, required_params=self.REQUIRED_TEST_PAY_PARAMS)

    async def test_pay_async(self, data: dict, token: str):
        """Payment Simulation (Sandbox)

        https://docs.maibmerchants.md/mia-qr-api/en/payment-simulation-sandbox"""

        return await self._execute_operation_async(endpoint=MaibMiaSdk.MIA_TEST_PAY, data=data, token=token, required_params=self.REQUIRED_TEST_PAY_PARAMS)

    def payment_details(self, pay_id: str, token: str):
        """Retrieve Payment Details by ID

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/information-retrieval-get/retrieve-payment-details-by-id"""

        return self._execute_entity_id_operation(endpoint=MaibMiaSdk.MIA_PAYMENTS_ID, entity_id=pay_id, token=token)

    async def payment_details_async(self, pay_id: str, token: str):
        """Retrieve Payment Details by ID

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/information-retrieval-get/retrieve-payment-details-by-id"""

        return await self._execute_entity_id_operation_async(endpoint=MaibMiaSdk.MIA_PAYMENTS_ID, entity_id=pay_id, token=token)

    def payment_refund(self, pay_id: str, data: dict, token: str):
        """Refund Completed Payment

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/payment-refund/refund-completed-payment"""

        return self._execute_entity_id_operation(endpoint=MaibMiaSdk.MIA_PAYMENTS_REFUND, entity_id=pay_id, token=token, method='POST', data=data)

    async def payment_refund_async(self, pay_id: str, data: dict, token: str):
        """Refund Completed Payment

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/payment-refund/refund-completed-payment"""

        return await self._execute_entity_id_operation_async(endpoint=MaibMiaSdk.MIA_PAYMENTS_REFUND, entity_id=pay_id, token=token, method='POST', data=data)

    def payment_list(self, params: dict, token: str):
        """Retrieve List of Payments with Filtering Options

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/information-retrieval-get/retrieve-list-of-payments-with-filtering-options"""

        return self._execute_operation(endpoint=MaibMiaSdk.MIA_PAYMENTS, data=None, token=token, required_params=None, method='GET', params=params)

    async def payment_list_async(self, params: dict, token: str):
        """Retrieve List of Payments with Filtering Options

        https://docs.maibmerchants.md/mia-qr-api/en/endpoints/information-retrieval-get/retrieve-list-of-payments-with-filtering-options"""

        return await self._execute_operation_async(endpoint=MaibMiaSdk.MIA_PAYMENTS, data=None, token=token, required_params=None, method='GET', params=params)
    #endregion

    #region RTP
    def rtp_create(self, data: dict, token: str):
        """Creates an individual payment request (Request to Pay), which will be sent to the end user through the banking application."""
        return self._execute_operation(endpoint=MaibMiaSdk.MIA_RTP, data=data, token=token, required_params=self.REQUIRED_RTP_PARAMS)

    async def rtp_create_async(self, data: dict, token: str):
        """Creates an individual payment request (Request to Pay), which will be sent to the end user through the banking application."""
        return await self._execute_operation_async(endpoint=MaibMiaSdk.MIA_RTP, data=data, token=token, required_params=self.REQUIRED_RTP_PARAMS)

    def rtp_status(self, rtp_id: str, token: str):
        """Get the current status of an RTP request."""
        return self._execute_entity_id_operation(endpoint=MaibMiaSdk.MIA_RTP_ID, entity_id=rtp_id, token=token)

    async def rtp_status_async(self, rtp_id: str, token: str):
        """Get the current status of an RTP request."""
        return await self._execute_entity_id_operation_async(endpoint=MaibMiaSdk.MIA_RTP_ID, entity_id=rtp_id, token=token)

    def rtp_cancel(self, rtp_id: str, data: dict, token: str):
        """Cancels an RTP request that is in pending status. The request cannot be canceled if it has already been accepted, rejected, or expired."""
        return self._execute_entity_id_operation(endpoint=MaibMiaSdk.MIA_RTP_CANCEL, entity_id=rtp_id, token=token, method='POST', data=data)

    async def rtp_cancel_async(self, rtp_id: str, data: dict, token: str):
        """Cancels an RTP request that is in pending status. The request cannot be canceled if it has already been accepted, rejected, or expired."""
        return await self._execute_entity_id_operation_async(endpoint=MaibMiaSdk.MIA_RTP_CANCEL, entity_id=rtp_id, token=token, method='POST', data=data)

    def rtp_list(self, params: dict, token: str):
        """Returns the list of RTP requests for the merchant, with filtering options."""
        return self._execute_operation(endpoint=MaibMiaSdk.MIA_RTP, data=None, token=token, required_params=None, method='GET', params=params)

    async def rtp_list_async(self, params: dict, token: str):
        """Returns the list of RTP requests for the merchant, with filtering options."""
        return await self._execute_operation_async(endpoint=MaibMiaSdk.MIA_RTP, data=None, token=token, required_params=None, method='GET', params=params)

    def rtp_refund(self, pay_id: str, data: dict, token: str):
        """Initiate Refund for a RTP with Accepted status"""
        return self._execute_entity_id_operation(endpoint=MaibMiaSdk.MIA_RTP_REFUND, entity_id=pay_id, token=token, method='POST', data=data)

    async def rtp_refund_async(self, pay_id: str, data: dict, token: str):
        """Initiate Refund for a RTP with Accepted status"""
        return await self._execute_entity_id_operation_async(endpoint=MaibMiaSdk.MIA_RTP_REFUND, entity_id=pay_id, token=token, method='POST', data=data)

    def rtp_test_accept(self, rtp_id: str, data: dict, token: str):
        """Test RTP simulation is only allowed in the sandbox environment."""
        return self._execute_entity_id_operation(endpoint=MaibMiaSdk.MIA_RTP_TEST_ACCEPT, entity_id=rtp_id, token=token, method='POST', data=data)

    async def rtp_test_accept_async(self, rtp_id: str, data: dict, token: str):
        """Test RTP simulation is only allowed in the sandbox environment."""
        return await self._execute_entity_id_operation_async(endpoint=MaibMiaSdk.MIA_RTP_TEST_ACCEPT, entity_id=rtp_id, token=token, method='POST', data=data)

    def rtp_test_reject(self, rtp_id: str, token: str):
        """Test RTP simulation is only allowed in the sandbox environment."""
        return self._execute_entity_id_operation(endpoint=MaibMiaSdk.MIA_RTP_TEST_REJECT, entity_id=rtp_id, token=token, method='POST')

    async def rtp_test_reject_async(self, rtp_id: str, token: str):
        """Test RTP simulation is only allowed in the sandbox environment."""
        return await self._execute_entity_id_operation_async(endpoint=MaibMiaSdk.MIA_RTP_TEST_REJECT, entity_id=rtp_id, token=token, method='POST')
    #endregion

    #region Sync operation
    def _execute_operation(self, endpoint: str, data: dict, token: str, required_params: list, method: str = 'POST', params: dict = None):
        self._validate_params(data=data, required_params=required_params)
        self._validate_access_token(token=token)
        return self._send_request(method=method, endpoint=endpoint, data=data, params=params, token=token)

    def _execute_entity_id_operation(self, endpoint: str, entity_id: str, token: str, method: str = 'GET', data: dict = None, params: dict = None):
        self._validate_id_param(entity_id=entity_id)
        self._validate_access_token(token=token)
        return self._send_request(method=method, endpoint=endpoint, token=token, data=data, params=params, entity_id=entity_id)

    def _send_request(self, method: str, endpoint: str, token: str, data: dict = None, params: dict = None, entity_id: str = None):
        """Sends a request to the specified endpoint."""

        try:
            response = self._client.send_request(method=method, url=endpoint, data=data, params=params, token=token, entity_id=entity_id)
        except Exception as ex:
            raise MaibMiaPaymentException(f'HTTP error while sending {method} request to endpoint {endpoint}: {ex}') from ex

        return self._client.handle_response(response, endpoint)
    #endregion

    #region Async operation
    async def _execute_operation_async(self, endpoint: str, data: dict, token: str, required_params: list, method: str = 'POST', params: dict = None):
        self._validate_params(data=data, required_params=required_params)
        self._validate_access_token(token=token)
        return await self._send_request_async(method=method, endpoint=endpoint, data=data, params=params, token=token)

    async def _execute_entity_id_operation_async(self, endpoint: str, entity_id: str, token: str, method: str = 'GET', data: dict = None, params: dict = None):
        self._validate_id_param(entity_id=entity_id)
        self._validate_access_token(token=token)
        return await self._send_request_async(method=method, endpoint=endpoint, token=token, data=data, params=params, entity_id=entity_id)

    async def _send_request_async(self, method: str, endpoint: str, token: str, data: dict = None, params: dict = None, entity_id: str = None):
        """Sends async request to the specified endpoint."""

        try:
            response = await self._client.send_request_async(method=method, url=endpoint, data=data, params=params, token=token, entity_id=entity_id)
        except Exception as ex:
            raise MaibMiaPaymentException(f'HTTP error while sending {method} request to endpoint {endpoint}: {ex}') from ex

        return self._client.handle_response(response, endpoint)
    #endregion

    #region Validation
    @staticmethod
    def _validate_access_token(token: str):
        """Validates the access token."""

        if not token or len(token) == 0:
            raise MaibMiaPaymentException('Access token is not valid. It should be a non-empty string.')

    @staticmethod
    def _validate_id_param(entity_id: str):
        """Validates the ID parameter."""

        if not entity_id:
            raise MaibMiaPaymentException('Missing ID.')

        if len(entity_id) == 0:
            raise MaibMiaPaymentException('Invalid ID parameter. Should be string of 36 characters.')

    @staticmethod
    def _validate_params(data: dict, required_params: list):
        """Validates the parameters."""

        if data and required_params:
            # Check that all required parameters are present
            for param in required_params:
                if data.get(param) is None:
                    raise MaibMiaPaymentException(f'Missing required parameter: {param}')

        return True
    #endregion
