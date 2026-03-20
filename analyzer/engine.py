from __future__ import annotations

from typing import Any

from analyzer.attachment_analyzer import analyze_attachments
from analyzer.domain_analyzer import analyze_domain
from analyzer.link_analyzer import analyze_links
from analyzer.text_analyzer import analyze_text
from mail_processor.parser import parse_email_payload


def risk_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def aggregate_score(module_results: dict[str, dict[str, Any]]) -> int:
    weights = {
        "domain": 0.30,
        "links": 0.30,
        "text": 0.25,
        "attachments": 0.15,
    }
    weighted = 0.0
    for module_name, module_weight in weights.items():
        weighted += float(module_results[module_name]["score"]) * module_weight
    return min(100, round(weighted))


def analyze_email_payload(raw_payload: dict[str, Any]) -> dict[str, Any]:
    payload = parse_email_payload(raw_payload)

    module_results: dict[str, dict[str, Any]] = {
        "domain": analyze_domain(
            sender_email=payload["from_email"],
            reply_to_email=payload["reply_to_email"],
            display_name=payload["display_name"],
        ),
        "links": analyze_links(payload["links"]),
        "text": analyze_text(subject=payload["subject"], body=payload["body"]),
        "attachments": analyze_attachments(payload["attachments"]),
    }

    global_score = aggregate_score(module_results)
    findings: list[str] = []
    for module_name, result in module_results.items():
        for finding in result["findings"]:
            findings.append(f"[{module_name}] {finding}")

    return {
        "risk_score": global_score,
        "risk_level": risk_level(global_score),
        "findings": findings,
        "modules": module_results,
    }
