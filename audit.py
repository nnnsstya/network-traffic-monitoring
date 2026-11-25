"""Простой журнал аудита JSONL с проверяемой цепочкой SHA-256.

Учебная реализация: для промышленного соответствия требованиям необходимы
ролевой доступ, ротация, хранение вне узла, независимое закрепление хешей,
политика ретенции и синхронизация времени.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        valid, reason, last_hash = self.verify(return_last_hash=True)
        if not valid:
            raise ValueError(f"Журнал аудита повреждён: {reason}")
        self.last_hash = last_hash

    def append(self, event_type: str, details: dict[str, Any], actor: str = "system") -> dict[str, Any]:
        # Не записывайте пароли, секретные ключи, биометрические шаблоны и токены.
        row = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "event_type": str(event_type),
            "actor": str(actor),
            "details": details,
            "previous_hash": self.last_hash,
        }
        row["hash"] = hashlib.sha256(canonical_json(row).encode("utf-8")).hexdigest()
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(canonical_json(row) + "\n")
        self.last_hash = row["hash"]
        return row

    def verify(self, return_last_hash: bool = False):
        previous = "0" * 64
        if self.path.exists():
            with self.path.open("r", encoding="utf-8") as stream:
                for number, line in enumerate(stream, 1):
                    try:
                        row = json.loads(line)
                        actual_hash = row["hash"]
                        item = {k: v for k, v in row.items() if k != "hash"}
                        expected_hash = hashlib.sha256(canonical_json(item).encode("utf-8")).hexdigest()
                        if row.get("previous_hash") != previous or actual_hash != expected_hash:
                            result = (False, f"строка {number}: нарушена хеш-цепочка", previous)
                            return result if return_last_hash else result[:2]
                        previous = actual_hash
                    except (ValueError, KeyError, TypeError) as exc:
                        result = (False, f"строка {number}: {exc}", previous)
                        return result if return_last_hash else result[:2]
        result = (True, "цепочка целостна", previous)
        return result if return_last_hash else result[:2]
