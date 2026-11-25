"""Финансовая модель ROI: три НЕ пересекающиеся категории экономии."""
from __future__ import annotations

from dataclasses import dataclass, asdict
import json
from pathlib import Path


@dataclass(frozen=True)
class ROIInputs:
    # Справочный показатель IBM/Ponemon 2026: средний совокупный ущерб от утечки.
    average_breach_cost_usd: float = 4_990_000
    major_breach_probability_before: float = .020
    major_breach_probability_after: float = .012
    # Ниже лишь простой/неаварийный простой, НЕ входящий в стоимость major breach.
    routine_downtime_hours_before: float = 40
    routine_downtime_hours_after: float = 16
    cost_per_routine_downtime_hour_usd: float = 200
    # Малые инциденты потери конфиденциальных данных ВНЕ cohort крупных утечек выше.
    minor_leak_losses_before_usd: float = 8_000
    minor_leak_losses_after_usd: float = 4_000
    implementation_cost_usd: float = 25_000
    annual_operating_cost_usd: float = 8_000
    annual_hours: float = 8_760


def calculate_roi(params: ROIInputs) -> dict:
    d = asdict(params)
    if any(v < 0 for v in d.values()):
        raise ValueError("Расходы, вероятность и часы не могут быть отрицательными")
    if any(not 0 <= p <= 1 for p in (params.major_breach_probability_before,
                                      params.major_breach_probability_after)):
        raise ValueError("Вероятности должны лежать от 0 до 1")
    if params.annual_hours <= 0 or params.implementation_cost_usd + params.annual_operating_cost_usd <= 0:
        raise ValueError("Необходимо задать число часов в году и положительные затраты")
    if max(params.routine_downtime_hours_before, params.routine_downtime_hours_after) > params.annual_hours:
        raise ValueError("Простой не должен превышать число часов в году")
    breach_savings = (params.major_breach_probability_before - params.major_breach_probability_after) * params.average_breach_cost_usd
    availability_savings = (params.routine_downtime_hours_before - params.routine_downtime_hours_after) * params.cost_per_routine_downtime_hour_usd
    minor_leak_savings = params.minor_leak_losses_before_usd - params.minor_leak_losses_after_usd
    benefits = breach_savings + availability_savings + minor_leak_savings
    expenses = params.implementation_cost_usd + params.annual_operating_cost_usd
    net = benefits - expenses
    roi_pct = 100 * net / expenses
    annual_net_cashflow = benefits - params.annual_operating_cost_usd
    payback_months = (12 * params.implementation_cost_usd / annual_net_cashflow
                      if annual_net_cashflow > 0 else None)
    return {
        "scenario": "Учебная модель; все допущения, кроме среднего ущерба IBM/Ponemon, придуманы для кейса",
        "source_benchmark": "IBM & Ponemon Institute, Cost of a Data Breach Report 2026, глобально $4.99 млн",
        "currency": "USD",
        "inputs": d,
        "annual_expected_major_breach_cost_before": round(params.major_breach_probability_before * params.average_breach_cost_usd, 2),
        "annual_expected_major_breach_cost_after": round(params.major_breach_probability_after * params.average_breach_cost_usd, 2),
        "annual_breach_savings_usd": round(breach_savings, 2),
        "routine_downtime_savings_usd": round(availability_savings, 2),
        "minor_data_leak_savings_usd": round(minor_leak_savings, 2),
        "total_annual_benefit_usd": round(benefits, 2),
        "first_year_cost_usd": round(expenses, 2),
        "first_year_net_benefit_usd": round(net, 2),
        "first_year_roi_pct": round(roi_pct, 2),
        "availability_before_pct": round(100 * (1 - params.routine_downtime_hours_before / params.annual_hours), 4),
        "availability_after_pct": round(100 * (1 - params.routine_downtime_hours_after / params.annual_hours), 4),
        "availability_delta_percentage_points": round(100 * (params.routine_downtime_hours_before - params.routine_downtime_hours_after) / params.annual_hours, 4),
        "payback_months": round(payback_months, 2) if payback_months is not None else None,
        "double_count_warning": "Крупная утечка включает связанные с ней простой и потери. Добавлены только НЕ связанные с ней часы простоя и малые инциденты.",
    }


def load_scenario(path: str | Path) -> ROIInputs:
    with Path(path).open(encoding="utf-8") as stream:
        return ROIInputs(**json.load(stream))


def report_text(result: dict) -> str:
    def m(key: str) -> str:
        return f"${result[key]:,.2f}"
    return "\n".join([
        "ЗАДАНИЕ 2. ROI ВНЕДРЕНИЯ СИСТЕМЫ МОНИТОРИНГА (1-й год)",
        "Предприятие: ТехноПрофи, 200 сотрудников (учебный кейс)",
        "Источник среднего ущерба от подтверждённой утечки: IBM/Ponemon 2026, $4,990,000.",
        "ВНИМАНИЕ: это мировой средний показатель, а не индивидуальный прогноз для малого/среднего бизнеса.",
        "Все остальные исходные числа являются УСЛОВНЫМИ, допущениями для учебного расчёта.",
        "", "Формулы:",
        "Снижение ожидаемого ущерба = (Pдо - Pпосле) × стоимость крупной утечки.",
        "Экономия простоя = (часы до - часы после) × стоимость часа.",
        "Экономия малых утечек = потери до - потери после.",
        "ROI = (суммарная экономия - затраты 1-го года) / затраты 1-го года × 100%.",
        "Availability = (8760 - часы простоя) / 8760 × 100%.",
        "", "Подстановка и результаты:",
        f"Предотвращённый ожидаемый ущерб от крупных утечек: {m('annual_breach_savings_usd')}",
        f"Экономия от обычного простоя: {m('routine_downtime_savings_usd')}",
        f"Снижение иных мелких потерь данных: {m('minor_data_leak_savings_usd')}",
        f"ИТОГО выгода за год: {m('total_annual_benefit_usd')}",
        f"Стоимость внедрения и обслуживания за первый год: {m('first_year_cost_usd')}",
        f"Чистая выгода: {m('first_year_net_benefit_usd')}",
        f"ROI: {result['first_year_roi_pct']:.2f}%",
        f"Доступность до: {result['availability_before_pct']:.4f}%",
        f"Доступность после: {result['availability_after_pct']:.4f}%",
        f"Изменение availability: +{result['availability_delta_percentage_points']:.4f} п.п.",
        f"Простой срок окупаемости: {result['payback_months']} мес.",
        "", "Методическое замечание: категории не пересекаются; двойной подсчёт устранён.",
    ]) + "\n"
