"""Адаптация учебного NetworkTrafficAnalyzer из лекции от 17.11.2026.

Строка DataFrame интерпретируется как одно сетевое событие/пакет в модели.
В промышленной сети нужна отдельная система сбора пакетов/NetFlow.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


class NetworkTrafficAnalyzer:
    def __init__(self, company_name: str = "ТехноПрофи", audit=None):
        self.company_name = company_name
        self.audit = audit
        self.traffic_df = pd.DataFrame()
        self.policy_violations: list[dict] = []
        self.security_policies = {
            "max_daily_external_traffic": 10 * 1024 ** 3,
            "blocked_ports": [21, 23, 135, 139, 445],
            "work_hours": {"start": 9, "end": 18},
            "allowed_protocols": ["HTTP", "HTTPS", "SSH", "SMTP", "DNS"],
        }
        self.anomaly_patterns = {
            "port_scan": {"unique_ports": 50, "unique_destinations": 10, "window_minutes": 5},
            # Измеряется именно в пакетах за секунду (pps), а не за минуту.
            "ddos_attack": {"pps_threshold": 400, "min_source_ips": 15, "window_seconds": 1},
        }
        self._event_keys: set[tuple[str, str, str]] = set()

    def simulate_traffic_data(self, hours: int = 24, users: int = 50, rows: int = 10_000) -> pd.DataFrame:
        if hours <= 0 or not 1 <= users <= 200 or rows < 0:
            raise ValueError("hours > 0, 1 <= users <= 200, rows >= 0")
        rng = np.random.default_rng(42)
        start = datetime.now(timezone.utc) - timedelta(hours=hours)
        departments = np.array(["Финансы", "IT", "Маркетинг", "HR", "Продажи", "Руководство"])
        protocols = np.array(["HTTP", "HTTPS", "SSH", "SMTP", "FTP", "DNS", "RDP"])
        port_map = {"HTTP": 80, "HTTPS": 443, "SSH": 22, "SMTP": 25, "FTP": 21, "DNS": 53, "RDP": 3389}
        selected_protocols = rng.choice(protocols, size=rows, p=[0.3, 0.4, 0.05, 0.05, 0.05, 0.1, 0.05])
        external = rng.random(rows) < .30
        destination_hosts = rng.integers(1, users + 1, size=rows)
        external_hosts = rng.integers(1, 255, size=rows)
        self.traffic_df = pd.DataFrame({
            "timestamp": pd.to_datetime(start) + pd.to_timedelta(rng.integers(0, hours * 3600, size=rows), unit="s"),
            "source_ip": [f"192.168.1.{i}" for i in rng.integers(1, users + 1, size=rows)],
            # TEST-NET-2: учебные адреса, не реальный Интернет.
            "destination_ip": [f"198.51.100.{e}" if flag else f"192.168.1.{internal}"
                               for flag, e, internal in zip(external, external_hosts, destination_hosts)],
            "protocol": selected_protocols,
            "port": [port_map[p] for p in selected_protocols],
            "size_bytes": np.clip(rng.lognormal(mean=10, sigma=2, size=rows).astype("int64"), 1, 65535),
            "department": rng.choice(departments, size=rows, p=[.1, .2, .15, .1, .3, .15]),
        }).sort_values("timestamp").reset_index(drop=True)
        self._audit("TRAFFIC_GENERATED", {"packets": rows, "hours": hours, "simulation": True})
        return self.traffic_df

    def inject_demo_attacks(self, ddos_seconds: int = 3, pps: int = 620) -> None:
        """Добавляет безопасные *записи*, НЕ отправляет настоящие сетевые пакеты."""
        if self.traffic_df.empty:
            raise ValueError("Сначала вызовите simulate_traffic_data")
        if ddos_seconds < 1 or pps < 1:
            raise ValueError("ddos_seconds и pps должны быть положительными")
        seed = pd.Timestamp.now(tz="UTC").floor("s") - pd.Timedelta(seconds=ddos_seconds + 2)
        injected: list[dict] = []
        for sec in range(ddos_seconds):
            for i in range(pps):
                injected.append({
                    "timestamp": seed + pd.Timedelta(seconds=sec),
                    "source_ip": f"203.0.113.{(i % 170) + 1}",
                    "destination_ip": "192.168.1.10",
                    "protocol": "HTTPS", "port": 443, "size_bytes": 512,
                    "department": "IT",
                })
        # Отдельная демонстрация сканирования портов (исключительно в DataFrame).
        for i in range(90):
            injected.append({
                "timestamp": seed - pd.Timedelta(minutes=2) + pd.Timedelta(seconds=i),
                "source_ip": "203.0.113.200",
                "destination_ip": f"192.168.1.{(i % 30) + 1}",
                "protocol": "TCP", "port": 10_000 + i, "size_bytes": 64,
                "department": "IT",
            })
        self.traffic_df = pd.concat([self.traffic_df, pd.DataFrame(injected)], ignore_index=True)
        self.traffic_df["timestamp"] = pd.to_datetime(self.traffic_df["timestamp"], utc=True)
        self.traffic_df = self.traffic_df.sort_values("timestamp").reset_index(drop=True)
        self._audit("DEMO_ANOMALIES_INJECTED", {"ddos_packets": ddos_seconds * pps, "port_scan_packets": 90})

    def _audit(self, event_type: str, details: dict) -> None:
        if self.audit:
            self.audit.append(event_type, details)

    def _add_violation(self, kind: str, timestamp, source: str, details: str,
                       severity: str = "HIGH", **extra) -> dict | None:
        stamp = pd.Timestamp(timestamp).isoformat()
        key = (kind, stamp, source)
        if key in self._event_keys:
            return None
        event = {
            "type": kind, "timestamp": stamp, "source": source,
            "details": details, "severity": severity, **extra,
        }
        self._event_keys.add(key)
        self.policy_violations.append(event)
        self._audit("SECURITY_EVENT", event)
        return event

    def analyze_traffic_patterns(self) -> dict:
        if self.traffic_df.empty:
            raise ValueError("Данные трафика отсутствуют")
        df = self.traffic_df
        df["is_external"] = ~df["destination_ip"].astype(str).str.startswith("192.168.1.")
        total = int(df["size_bytes"].sum())
        return {
            "total_packets": int(len(df)),
            "protocol_distribution": df["protocol"].value_counts().to_dict(),
            "departments_mb": (df.groupby("department")["size_bytes"].sum() / 1024 ** 2).round(3).to_dict(),
            "internal_packets": int((~df["is_external"]).sum()),
            "external_packets": int(df["is_external"].sum()),
            "total_traffic_mb": round(total / 1024 ** 2, 3),
        }

    def detect_policy_violations(self) -> list[dict]:
        if self.traffic_df.empty:
            raise ValueError("Данные трафика отсутствуют")
        df = self.traffic_df
        for row in df[df["port"].isin(self.security_policies["blocked_ports"])].head(5).itertuples():
            self._add_violation("BLOCKED_PORT", row.timestamp, row.source_ip,
                                f"Использование заблокированного порта {row.port}")
        hours = df["timestamp"].dt.hour
        after_hours = df[(hours < 9) | (hours >= 18)]
        if len(after_hours) > 100:
            for dept, count in after_hours.groupby("department").size().items():
                if count > 50:
                    self._add_violation("AFTER_HOURS_ACTIVITY", after_hours["timestamp"].min(),
                                        f"Отдел {dept}", f"{count} событий вне рабочего времени", "MEDIUM")
        windows = df.assign(five_min=df["timestamp"].dt.floor("5min"))
        scan = windows.groupby(["source_ip", "five_min"]).agg(
            unique_ports=("port", "nunique"), unique_destinations=("destination_ip", "nunique"))
        scan = scan.reset_index()
        for row in scan.itertuples():
            if row.unique_ports >= self.anomaly_patterns["port_scan"]["unique_ports"] and \
               row.unique_destinations >= self.anomaly_patterns["port_scan"]["unique_destinations"]:
                self._add_violation("PORT_SCAN", row.five_min, row.source_ip,
                                    f"{row.unique_ports} уникальных портов, {row.unique_destinations} целей за 5 минут")
        return self.policy_violations

    def detect_ddos(self) -> list[dict]:
        """Подозрение на DDoS при pps>=порог И множестве уникальных IP-источников.

        Это эвристика: не гарантирует подтверждения DDoS, особенно за NAT.
        """
        if self.traffic_df.empty:
            raise ValueError("Данные трафика отсутствуют")
        df = self.traffic_df.assign(second=self.traffic_df["timestamp"].dt.floor("s"))
        per_second = df.groupby(["destination_ip", "second"]).agg(
            pps=("source_ip", "size"), sources=("source_ip", "nunique")
        ).reset_index()
        rules = self.anomaly_patterns["ddos_attack"]
        candidates = per_second[(per_second["pps"] >= rules["pps_threshold"]) &
                                (per_second["sources"] >= rules["min_source_ips"])]
        found = []
        for row in candidates.itertuples():
            item = self._add_violation("DDOS_SUSPECTED", row.second, row.destination_ip,
                                       f"{row.pps} пакетов/с от {row.sources} IP-источников",
                                       "CRITICAL", destination_ip=row.destination_ip,
                                       pps=int(row.pps), unique_sources=int(row.sources))
            if item:
                found.append(item)
        return found

    def generate_security_report(self, pattern_summary: dict) -> str:
        counts = Counter(e["type"] for e in self.policy_violations)
        text = [
            "ОТЧЁТ ПО БЕЗОПАСНОСТИ СЕТЕВОГО ТРАФИКА", f"Предприятие: {self.company_name}",
            "Исходный пример: лекция от 17.11.2026; данные и атаки смоделированы.",
            f"Всего пакетов/событий: {pattern_summary['total_packets']}",
            f"Общий объём трафика: {pattern_summary['total_traffic_mb']} МБ",
            f"Внутренних: {pattern_summary['internal_packets']}; внешних: {pattern_summary['external_packets']}",
            "", "Обнаруженные сигналы:",
        ]
        text += [f"  {kind}: {count}" for kind, count in sorted(counts.items())] or ["  Нет"]
        text += ["", "Рекомендации:",
                 "1. Проверить аномальный pps с учётом базового профиля и нагрузки.",
                 "2. Настроить rate limiting, WAF / IDS/IPS и фильтрацию на границе сети.",
                 "3. Включить централизованный журнал с ротацией и защитой от изменений.",
                 "4. Изучать сигналы MISP/OTX перед блокировкой; исключить ложные срабатывания.",
                 "5. Согласовать передачу данных в облако/мессенджеры с политикой ИБ."]
        return "\n".join(text) + "\n"

    def visualize_traffic(self, out_file: str | Path):
        """Четыре диаграммы из лекции плюс пятая диаграмма pps для DDoS."""
        out_file = Path(out_file)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        df = self.traffic_df
        fig, axes = plt.subplots(2, 3, figsize=(16, 9))
        hourly = df.groupby(df["timestamp"].dt.hour).size()
        axes[0, 0].bar(hourly.index, hourly.values)
        axes[0, 0].set_title("Пакеты по часам")
        axes[0, 0].set_xlabel("Час")
        protocol = df["protocol"].value_counts()
        axes[0, 1].pie(protocol.values, labels=protocol.index, autopct="%1.1f%%")
        axes[0, 1].set_title("Протоколы")
        departments = (df.groupby("department")["size_bytes"].sum() / 1024 ** 2)
        axes[0, 2].bar(departments.index, departments.values)
        axes[0, 2].tick_params(axis="x", labelrotation=35)
        axes[0, 2].set_title("Объём по отделам (МБ)")
        internal = df["destination_ip"].str.startswith("192.168.1.")
        axes[1, 0].bar(["Внутренний", "Внешний"], [int(internal.sum()), int((~internal).sum())])
        axes[1, 0].set_title("Направление трафика")
        pps = df.groupby(df["timestamp"].dt.floor("s")).size().sort_values(ascending=False).head(12)
        axes[1, 1].bar([str(i.time()) for i in pps.index], pps.values)
        axes[1, 1].axhline(self.anomaly_patterns["ddos_attack"]["pps_threshold"],
                            color="red", linestyle="--", label="Порог pps")
        axes[1, 1].tick_params(axis="x", labelrotation=60)
        axes[1, 1].legend()
        axes[1, 1].set_title("12 секунд с наибольшим pps (все цели)")
        types = Counter(event["type"] for event in self.policy_violations)
        axes[1, 2].bar(list(types) or ["Нет"], list(types.values()) or [0])
        axes[1, 2].tick_params(axis="x", labelrotation=40)
        axes[1, 2].set_title("Сигналы безопасности")
        fig.suptitle(f"Мониторинг трафика: {self.company_name}")
        fig.tight_layout()
        fig.savefig(out_file, dpi=130, bbox_inches="tight")
        plt.close(fig)
        return out_file
