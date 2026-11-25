"""Оповещения Telegram/Slack с безопасным локальным демонстрационным режимом."""
from __future__ import annotations

import os
import requests


class AlertDispatcher:
    def __init__(self, live: bool = False, timeout: int = 8):
        self.live = live
        self.timeout = timeout

    def notify(self, incident: dict) -> dict[str, str]:
        message = (f"[ТехноПрофи] {incident['severity']}: {incident['type']}\n"
                   f"Цель/источник: {incident['source']}\n"
                   f"Время: {incident['timestamp']}\n"
                   f"Описание: {incident['details']}")
        if not self.live:
            return {"mode": "DEMO", "telegram": "не отправлено", "slack": "не отправлено", "preview": message}

        result: dict[str, str] = {"mode": "LIVE"}
        bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
        webhook = os.getenv("SLACK_WEBHOOK_URL", "")
        if bot_token and chat_id:
            try:
                response = requests.post(f"https://api.telegram.org/bot{bot_token}/sendMessage",
                                         json={"chat_id": chat_id, "text": message}, timeout=self.timeout)
                response.raise_for_status()
                result["telegram"] = "отправлено"
            except requests.RequestException:
                # Не включаем исключение: оно может содержать URL с секретным токеном.
                result["telegram"] = "ошибка отправки (секрет скрыт)"
        else:
            result["telegram"] = "не настроено"
        if webhook:
            try:
                if not webhook.startswith("https://hooks.slack.com/services/"):
                    raise ValueError("Недопустимый Slack webhook URL")
                response = requests.post(webhook, json={"text": message}, timeout=self.timeout)
                response.raise_for_status()
                result["slack"] = "отправлено"
            except (requests.RequestException, ValueError):
                result["slack"] = "ошибка отправки (секрет скрыт)"
        else:
            result["slack"] = "не настроено"
        return result
