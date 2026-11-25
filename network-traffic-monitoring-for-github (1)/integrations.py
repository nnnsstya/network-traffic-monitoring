"""Задание 3: интеграции. Безопасный offline demo по умолчанию.

Никакие живые сервисы не вызываются без двух подтверждений:
CLI --live И переменная ALLOW_EXTERNAL_CALLS=1.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import os
from urllib.parse import urlparse

import requests


class BiometricAuthAdapter:
    """Принимает токен-assertion от внешнего вендора, а НЕ биометрические данные.

    Только доверенный вендор может проверить биометрию. Demo-режим не даёт
    разрешение на доступ. Production-интеграция требует тестирования IdP/политик.
    """

    def __init__(self, live: bool = False):
        self.live = live

    def verify(self, user_id: str, external_assertion: str | None = None) -> dict:
        if not self.live:
            return {
                "status": "DEMO_ONLY", "user_id": user_id, "authenticated": False,
                "simulated_result": "внешний провайдер подтвердил бы личность",
                "note": "Никакая биометрия не собирается, доступ не предоставляется",
            }
        url = os.getenv("BIOMETRIC_VERIFY_URL", "")
        api_key = os.getenv("BIOMETRIC_API_KEY", "")
        if (not url or not api_key or not external_assertion or
                urlparse(url).scheme != "https" or not urlparse(url).hostname):
            return {"status": "NOT_CONFIGURED", "authenticated": False, "user_id": user_id}
        try:
            resp = requests.post(url, json={"user_id": user_id, "assertion": external_assertion},
                                 headers={"Authorization": f"Bearer {api_key}"}, timeout=8)
            resp.raise_for_status()
            body = resp.json()
            # Лишь результат проверки у доверенного провайдера; API-контракт условный.
            valid = body.get("verified") is True and body.get("user_id") == user_id
            return {"status": "VERIFIED" if valid else "DENIED", "authenticated": valid, "user_id": user_id}
        except (requests.RequestException, ValueError):
            return {"status": "PROVIDER_ERROR", "authenticated": False, "user_id": user_id}


class CloudMonitorExporter:
    """Отправка агрегированных показателей в CloudWatch и Azure Log Analytics."""

    def __init__(self, live: bool = False):
        self.live = live

    def export(self, ddos_count: int, peak_pps: int, total_packets: int) -> dict:
        metrics = {
            "TimeGenerated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "Company": "TechnoProfi", "DdosAlerts": int(ddos_count),
            "PeakPps": int(peak_pps), "TotalPackets": int(total_packets),
        }
        if not self.live:
            return {"aws": "DEMO_ONLY", "azure": "DEMO_ONLY", "metric_preview": metrics}

        result = {"aws": "NOT_CONFIGURED", "azure": "NOT_CONFIGURED"}
        if os.getenv("AWS_REGION"):
            try:
                import boto3
                client = boto3.client("cloudwatch", region_name=os.environ["AWS_REGION"])
                client.put_metric_data(Namespace="TechnoProfi/NetworkSecurity", MetricData=[
                    {"MetricName": "DdosAlerts", "Value": float(ddos_count), "Unit": "Count"},
                    {"MetricName": "PeakPps", "Value": float(peak_pps), "Unit": "Count/Second"},
                    {"MetricName": "TotalPackets", "Value": float(total_packets), "Unit": "Count"},
                ])
                result["aws"] = "SENT"
            except Exception as exc:
                result["aws"] = f"ERROR: {type(exc).__name__}"  # Не раскрывать секреты.

        endpoint, rule_id, stream = (os.getenv("AZURE_LOG_ENDPOINT"),
                                     os.getenv("AZURE_DCR_ID"), os.getenv("AZURE_STREAM_NAME"))
        if all([endpoint, rule_id, stream]):
            try:
                from azure.identity import DefaultAzureCredential
                from azure.monitor.ingestion import LogsIngestionClient
                with LogsIngestionClient(endpoint=endpoint, credential=DefaultAzureCredential()) as client:
                    client.upload(rule_id=rule_id, stream_name=stream, logs=[metrics])
                result["azure"] = "SENT"
            except Exception as exc:
                result["azure"] = f"ERROR: {type(exc).__name__}"
        return result


class ThreatIntelAdapter:
    """MISP / AlienVault OTX: обогащение IP индикаторами (не автоматическая блокировка)."""

    MOCK = {"203.0.113.66": {"misp_hits": 2, "otx_pulses": 3}}

    def __init__(self, live: bool = False):
        self.live = live

    def lookup_ip(self, ip: str) -> dict:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return {"ip": ip, "status": "IPV4_ONLY", "suspicious": False}
        if not self.live:
            demo = self.MOCK.get(ip, {"misp_hits": 0, "otx_pulses": 0})
            return {"ip": ip, "status": "DEMO_ONLY", "suspicious": bool(sum(demo.values())), **demo}
        if not addr.is_global:
            # Не отправлять локальные или тестовые адреса во внешние сервисы.
            return {"ip": ip, "status": "NON_PUBLIC_IP_SKIPPED", "suspicious": False}
        misp_hits = self._query_misp(ip)
        otx_pulses = self._query_otx(ip)
        if misp_hits is None and otx_pulses is None:
            return {"ip": ip, "status": "NOT_CONFIGURED", "suspicious": False}
        return {"ip": ip, "status": "CHECKED", "misp_hits": misp_hits,
                "otx_pulses": otx_pulses, "suspicious": (misp_hits or 0) > 0 or (otx_pulses or 0) > 0}

    def _query_misp(self, ip: str) -> int | None:
        base = os.getenv("MISP_URL", "").rstrip("/")
        token = os.getenv("MISP_API_KEY", "")
        if not base or not token:
            return None
        if urlparse(base).scheme != "https":
            return None
        try:
            response = requests.post(
                base + "/attributes/restSearch",
                json={"returnFormat": "json", "value": ip, "limit": 20},
                headers={"Authorization": token, "Accept": "application/json",
                         "Content-Type": "application/json"}, timeout=8,
            )
            response.raise_for_status()
            data = response.json()
            attrs = data.get("response", {}).get("Attribute", []) if isinstance(data.get("response"), dict) else data.get("response", [])
            return sum(1 for item in attrs if isinstance(item, dict) and item.get("value") == ip)
        except (requests.RequestException, ValueError, TypeError, AttributeError):
            return None

    def _query_otx(self, ip: str) -> int | None:
        key = os.getenv("OTX_API_KEY", "")
        if not key:
            return None
        try:
            response = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                                    headers={"X-OTX-API-KEY": key}, timeout=8)
            response.raise_for_status()
            return int(response.json().get("pulse_info", {}).get("count", 0))
        except (requests.RequestException, ValueError, TypeError, AttributeError):
            return None
