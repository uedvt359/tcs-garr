from abc import ABC, abstractmethod
import requests
import logging
import time
from dataclasses import dataclass
from enum import Enum
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NotificationLevel(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    SUCCESS = "success"


@dataclass
class NotificationData:
    def __init__(self, title, message, level, details=None, channel=None, timestamp=None):
        self.title = title
        self.message = message
        self.level = level
        self.details = details or {}
        self.channel = channel
        self.timestamp = timestamp or datetime.now()


class NotificationProvider(ABC):
    def __init__(self, webhook_url):
        self.webhook_url = webhook_url
        self.timeout = 30
        self.retry_attempts = 3
        self.retry_delay = 1.0

    @abstractmethod
    def send_notification(self, notification):
        pass

    @abstractmethod
    def format_message(self, notification):
        pass

    def _send_request(self, payload, headers=None):
        if headers is None:
            headers = {"Content-Type": "application/json"}

        for attempt in range(self.retry_attempts):
            try:
                response = requests.post(
                    url=self.webhook_url,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout,
                )
                if response.status_code in [200, 201, 202, 204]:
                    logger.info(f"Notification sent via {self.__class__.__name__}")
                    return True
                else:
                    logger.warning(f"{self.__class__.__name__} error: {response.status_code} - {response.text}")
            except requests.exceptions.RequestException as e:
                logger.error(f"{self.__class__.__name__} request failed (attempt {attempt + 1}): {e}")
            if attempt < self.retry_attempts - 1:
                time.sleep(self.retry_delay * (2**attempt))

        logger.error(f"Failed to send via {self.__class__.__name__} after {self.retry_attempts} attempts")
        return False


class SlackProvider(NotificationProvider):
    def __init__(self, webhook_url):
        super().__init__(webhook_url)
        self.username = "TCS-GARR Notifier"
        self.default_channel = None

    def format_message(self, notification):
        level_config = {
            NotificationLevel.ERROR: {"emoji": "🚨", "color": "danger"},
            NotificationLevel.WARNING: {"emoji": "⚠️", "color": "warning"},
            NotificationLevel.INFO: {"emoji": "ℹ️", "color": "good"},
            NotificationLevel.SUCCESS: {"emoji": "✅", "color": "good"},
        }

        config = level_config[notification.level]

        fields = [{"title": f"{config['emoji']} {notification.title}", "value": notification.message, "short": False}]

        for key, value in notification.details.items():
            fields.append({"title": key.replace("_", " ").title(), "value": str(value), "short": len(str(value)) < 50})

        payload = {
            "username": self.username,
            "attachments": [
                {
                    "color": config["color"],
                    "fields": fields,
                    "footer": "TCS-GARR Notification",
                    "ts": int(notification.timestamp.timestamp()),
                }
            ],
        }

        if notification.channel or self.default_channel:
            payload["channel"] = notification.channel or self.default_channel

        return payload

    def send_notification(self, notification):
        payload = self.format_message(notification)
        return self._send_request(payload)


class GenericWebhookProvider(NotificationProvider):
    def __init__(self, webhook_url):
        super().__init__(webhook_url)

    def format_message(self, notification):
        payload = {
            "title": notification.title,
            "message": notification.message,
            "level": notification.level.value,
            "timestamp": notification.timestamp.isoformat(),
        }
        payload.update(notification.details)
        return payload

    def send_notification(self, notification):
        payload = self.format_message(notification)
        return self._send_request(payload)


class NotificationManager:
    PROVIDERS = {"slack": SlackProvider, "generic": GenericWebhookProvider}

    def __init__(self, webhook_type, webhook_url):
        if webhook_type not in self.PROVIDERS:
            raise ValueError(f"Unknown webhook type: {webhook_type}")
        self.provider = self.PROVIDERS[webhook_type](webhook_url)

    def send_notification(self, title, message, level=NotificationLevel.INFO, details=None, channel=None):
        notification = NotificationData(title=title, message=message, level=level, details=details or {}, channel=channel)
        return self.provider.send_notification(notification)

    def error(self, title, message, details):
        return self.send_notification(title, message, NotificationLevel.ERROR, details)

    def warning(self, title, message, details):
        return self.send_notification(title, message, NotificationLevel.WARNING, details)

    def info(self, title, message, details):
        return self.send_notification(title, message, NotificationLevel.INFO, details)

    def success(self, title, message, details):
        return self.send_notification(title, message, NotificationLevel.SUCCESS, details)
