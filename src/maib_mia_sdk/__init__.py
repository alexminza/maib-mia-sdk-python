"""Python SDK for maib MIA API"""

import logging

from .maib_mia_sdk import MaibMiaSdk, MaibMiaTokenException, MaibMiaPaymentException
from .maib_mia_auth import MaibMiaAuthRequest, MaibMiaAuth
from .maib_mia_api import MaibMiaApiRequest, MaibMiaApi

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class RedactingLoggingFilter(logging.Filter):
    _sensitive_keys: list = None
    _placeholder: str = None
    _show_chars: int = None

    _min_length: int = None

    def __init__(self, *args, sensitive_keys: list = ('clientSecret', 'accessToken', 'token'), placeholder: str = '****', show_chars: int = 4, **kwargs):
        super().__init__(*args, **kwargs)

        self._sensitive_keys = sensitive_keys
        self._placeholder = placeholder
        self._show_chars = show_chars

        self._min_length = len(placeholder) + show_chars

    def filter(self, record: logging.LogRecord):
        record.__dict__ = self._redact_data(record.__dict__)
        return True

    def _redact_data(self, data: dict[str, any]):
        if data is None or not isinstance(data, dict):
            return data

        redacted_data = {}
        for key, value in data.items():
            if key in self._sensitive_keys:
                redacted_data[key] = self._redact_value(value)
            elif isinstance(value, dict):
                redacted_data[key] = self._redact_data(value)
            else:
                redacted_data[key] = value

        return redacted_data

    def _redact_value(self, value: str):
        if value is None or not isinstance(value, str):
            return value

        if len(value) <= self._min_length:
            return self._placeholder

        return f'{self._placeholder}{value[-4:]}'
