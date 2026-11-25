"""Домашняя работа по теме «Обеспечение сетевого трафика предприятия».
Запуск: python main.py
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from analyzer import NetworkTrafficAnalyzer
from alerts import AlertDispatcher
from audit import AuditLog
from integrations import BiometricAuthAdapter, CloudMonitorExporter, ThreatIntelAdapter
from roi import calculate_roi, load_scenario, report_text
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description="Учебный мониторинг трафика предприятия")
    parser.add_argument("--output", default=str(BASE_DIR / "results"), help="Папка с отчётами")
    parser.add_argument("--live", action="store_true", help="Разрешить интеграции ТОЛЬКО при ALLOW_EXTERNAL_CALLS=1")
    parser.add_argument("--no-demo-attacks", action="store_true", help="Не вводить демонстрационные аномалии")
    args = parser.parse_args()
    load_dotenv(BASE_DIR / ".env")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    live = args.live and os.getenv("ALLOW_EXTERNAL_CALLS", "0") == "1"

    audit = AuditLog(output / "audit.jsonl")
    audit.append("ANALYSIS_STARTED", {"company": "ТехноПрофи", "live": live})
    analyzer = NetworkTrafficAnalyzer(company_name="ТехноПрофи", audit=audit)
    analyzer.simulate_traffic_data(hours=24, users=50)
    if not args.no_demo_attacks:
        analyzer.inject_demo_attacks()

    patterns = analyzer.analyze_traffic_patterns()
    analyzer.detect_policy_violations()
    ddos_events = analyzer.detect_ddos()
    analyzer.visualize_traffic(output / "network_traffic_analysis.png")
    (output / "security_report.txt").write_text(analyzer.generate_security_report(patterns), encoding="utf-8")
    analyzer.traffic_df.to_csv(output / "traffic_sample.csv", index=False)
    (output / "alerts.json").write_text(json.dumps(analyzer.policy_violations, ensure_ascii=False, indent=2), encoding="utf-8")

    # Оповещение: только одно уведомление об инциденте, даже если пиков несколько секунд.
    notifier = AlertDispatcher(live=live)
    notices = [notifier.notify(ddos_events[0])] if ddos_events else []
    audit.append("ALERTS_PROCESSED", {"sent_or_previewed": len(notices), "live": live})

    # Задание 2: ROI (исходные данные в JSON изменяются студентом).
    roi = calculate_roi(load_scenario(BASE_DIR / "config" / "roi_scenario.json"))
    (output / "roi_results.json").write_text(json.dumps(roi, ensure_ascii=False, indent=2), encoding="utf-8")
    (output / "roi_report.txt").write_text(report_text(roi), encoding="utf-8")

    # Задание 3: интеграции. По умолчанию результат симулируется локально.
    biometric = BiometricAuthAdapter(live=live).verify(user_id="demo_employee")
    intel = ThreatIntelAdapter(live=live).lookup_ip("203.0.113.66")
    # В live режиме тестовый IP адрес НЕ отправляется во внешние MISP/OTX.
    peak_pps = int(analyzer.traffic_df.groupby(analyzer.traffic_df["timestamp"].dt.floor("s")).size().max())
    cloud = CloudMonitorExporter(live=live).export(len(ddos_events), peak_pps, patterns["total_packets"])
    integration_results = {"biometric": biometric, "threat_intelligence": intel, "cloud": cloud,
                           "notifications": notices}
    (output / "integration_results.json").write_text(json.dumps(integration_results, ensure_ascii=False, indent=2), encoding="utf-8")
    # В журнал не пишем bearer-токены, пароли, webhook URL или биометрические данные.
    audit.append("INTEGRATIONS_CHECKED", {"biometric_status": biometric["status"],
                                          "threat_intel_status": intel["status"],
                                          "cloud_status": {"aws": cloud["aws"], "azure": cloud["azure"]}})
    audit.append("ANALYSIS_FINISHED", {"events": len(analyzer.policy_violations), "roi_pct": roi["first_year_roi_pct"]})
    valid, audit_reason = audit.verify()

    print("=" * 65)
    print("ДОМАШНЕЕ ЗАДАНИЕ: ОБЕСПЕЧЕНИЕ СЕТЕВОГО ТРАФИКА")
    print("=" * 65)
    print(f"Компания: ТехноПрофи | сотрудников: 200 | событий: {patterns['total_packets']}")
    print(f"Пакетов/с (пиковое значение): {peak_pps}")
    print(f"Сигналов вероятной DDoS: {len(ddos_events)}")
    print(f"Всего сигналов безопасности: {len(analyzer.policy_violations)}")
    print(f"Журнал аудита: {audit_reason} ({'OK' if valid else 'ERROR'})")
    print(f"Telegram/Slack: {'живой режим' if live else 'только демонстрация, запросы не отправлены'}")
    print("MISP, OTX, AWS, Azure, биометрия:", "live" if live else "демо-адаптеры")
    print(f"Выгода за 1-й год: ${roi['total_annual_benefit_usd']:,.0f} | ROI: {roi['first_year_roi_pct']}%")
    print(f"Availability: {roi['availability_before_pct']}% → {roi['availability_after_pct']}%")
    print("Отчёты сохранены в:", output.resolve())
    if not valid:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
