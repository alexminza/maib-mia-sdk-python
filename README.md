# Python SDK for maib MIA API
* maib MIA QR API docs: https://docs.maibmerchants.md/mia-qr-api
* GitHub project https://github.com/alexminza/maib-mia-sdk-python
* PyPI package https://pypi.org/project/maib-mia-sdk/

## Installation
To easily install or upgrade to the latest release, use `pip`:

```shell
pip install --upgrade maib-mia-sdk
```

## Getting started
Import SDK:

```python
from maib_mia_sdk import MaibMiaSdk, MaibMiaAuthRequest, MaibMiaApiRequest
```

Add project configuration:

```python
import os, datetime

MAIB_MIA_CLIENT_ID = os.getenv('MAIB_MIA_CLIENT_ID')
MAIB_MIA_CLIENT_SECRET = os.getenv('MAIB_MIA_CLIENT_SECRET')
MAIB_MIA_SIGNATURE_KEY = os.getenv('MAIB_MIA_SIGNATURE_KEY')
```

## SDK usage examples
### Get Access Token with Client ID and Client Secret

```python
maib_mia_auth = MaibMiaAuthRequest \
    .create(base_url=MaibMiaSdk.SANDBOX_BASE_URL) \
    .generate_token(client_id=MAIB_MIA_CLIENT_ID, client_secret=MAIB_MIA_CLIENT_SECRET)

maib_mia_token = maib_mia_auth['accessToken']
```

### Create a dynamic order payment QR

```python
maib_mia_qr_data = {
    'type': 'Dynamic',
    'expiresAt': (datetime.datetime.now() + datetime.timedelta(hours=24)).isoformat(),
    'amountType': 'Fixed',
    'amount': 50.00,
    'currency': 'MDL',
    'orderId': '123',
    'description': 'Order #123',
    'callbackUrl': 'https://example.com/callback',
    'redirectUrl': 'https://example.com/success'
}

maib_mia_api_request = MaibMiaApiRequest.create(base_url=MaibMiaSdk.SANDBOX_BASE_URL)
maib_mia_create_qr_response = maib_mia_api_request.qr_create(
    data=maib_mia_qr_data,
    token=maib_mia_token)
```

### Create a RTP (Request To Pay)

```python
maib_mia_rtp_data = {
    'alias': '3736xxxxxxx',
    'amount': 50.00,
    'currency': 'MDL',
    'expiresAt': (datetime.datetime.now() + datetime.timedelta(hours=24)).isoformat(),
    'description': f'Order #123',
    'orderId': '123',
    'callbackUrl': 'https://example.com/callback',
    'redirectUrl': 'https://example.com/success'
}

maib_mia_create_rtp_response = maib_mia_api_request.rtp_create(
    data=maib_mia_rtp_data,
    token=maib_mia_token)
```

### Validate callback signature

```python
callback_data = {
    "result": {
        "qrId": "c3108b2f-6c2e-43a2-bdea-123456789012",
        "extensionId": "3fe7f013-23a6-4d09-a4a4-123456789012",
        "qrStatus": "Paid",
        "payId": "eb361f48-bb39-45e2-950b-123456789012",
        "referenceId": "MIA0001234567",
        "orderId": "123",
        "amount": 50.00,
        "commission": 0.1,
        "currency": "MDL",
        "payerName": "TEST QR PAYMENT",
        "payerIban": "MD88AG000000011621810140",
        "executedAt": "2025-04-18T14:04:11.81145+00:00",
        "terminalId": null
    },
    "signature": "fHM+l4L1ycFWZDRTh/Vr8oybq1Q1xySdjyvmFQCmZ4s="
}

validate_callback_result = MaibMiaSdk.validate_callback_signature(
    callback_data=callback_data,
    signature_key=MAIB_MIA_SIGNATURE_KEY)
```

### Perform a test QR payment

```python
maib_test_pay_data = {
    'qrId': maib_mia_create_qr_response['qrId'],
    'amount': maib_mia_qr_data['amount'],
    'iban': 'MD88AG000000011621810140',
    'currency': maib_mia_qr_data['currency'],
    'payerName': 'TEST QR PAYMENT'
}

maib_mia_test_pay_response = maib_mia_api_request.test_pay(
    data=maib_test_pay_data,
    token=maib_mia_token)
```

### Get payment details

```python
maib_mia_payment_details_response = maib_mia_api_request.payment_details(
    pay_id=maib_mia_test_pay_response['payId'],
    token=maib_mia_token)
```

### Refund payment

```python
maib_mia_pay_refund_data = {
    'reason': 'Test refund reason'
}

maib_mia_refund_details_response = maib_mia_api_request.payment_refund(
    pay_id=maib_mia_test_pay_response['payId'],
    data=maib_mia_pay_refund_data,
    token=maib_mia_token)
```
