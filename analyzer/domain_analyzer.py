from __future__ import annotations

import ipaddress
import re


SUSPICIOUS_TLDS = {"zip", "mov", "click", "country", "gq", "tk", "top", "work"}
MAJOR_BRANDS = {
	"microsoft",
	"google",
	"apple",
	"amazon",
	"paypal",
	"netflix",
	"meta",
	"facebook",
	"instagram",
	"linkedin",
}


def _risk_level(score: int) -> str:
	if score >= 75:
		return "critical"
	if score >= 50:
		return "high"
	if score >= 25:
		return "medium"
	return "low"


def _extract_domain(email_address: str | None) -> str:
	if not email_address or "@" not in email_address:
		return ""
	return email_address.rsplit("@", 1)[-1].strip().lower()


def _is_ip(value: str) -> bool:
	try:
		ipaddress.ip_address(value)
		return True
	except ValueError:
		return False


def analyze_domain(
	sender_email: str,
	reply_to_email: str | None = None,
	display_name: str | None = None,
) -> dict:
	"""Analyze sender domain metadata for phishing patterns."""
	findings: list[str] = []
	score = 0

	sender_domain = _extract_domain(sender_email)
	reply_to_domain = _extract_domain(reply_to_email)

	if not sender_domain:
		findings.append("No se pudo extraer dominio del remitente")
		score += 35
	else:
		if sender_domain.startswith("xn--") or ".xn--" in sender_domain:
			findings.append(f"Dominio remitente en punycode: {sender_domain}")
			score += 25

		if _is_ip(sender_domain):
			findings.append("Remitente usa IP como dominio")
			score += 25

		parts = [part for part in sender_domain.split(".") if part]
		if len(parts) < 2:
			findings.append("Dominio remitente con formato inusual")
			score += 15
		else:
			tld = parts[-1]
			if tld in SUSPICIOUS_TLDS:
				findings.append(f"TLD de riesgo en remitente: .{tld}")
				score += 12

			if len(parts) >= 4:
				findings.append("Dominio del remitente con exceso de subdominios")
				score += 6

			if any(ch.isdigit() for ch in parts[0]):
				findings.append("Nombre de dominio con patron numerico sospechoso")
				score += 5

	if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
		findings.append(
			f"Reply-To distinto al dominio del remitente: {reply_to_domain} != {sender_domain}"
		)
		score += 20

	lowered_display_name = (display_name or "").lower()
	brand_hits = [brand for brand in MAJOR_BRANDS if brand in lowered_display_name]
	if brand_hits and sender_domain:
		if not any(brand in sender_domain for brand in brand_hits):
			findings.append(
				"Posible suplantacion por display name: " + ", ".join(sorted(brand_hits))
			)
			score += 18

	if sender_domain and re.search(r"[-_]{2,}", sender_domain):
		findings.append("Dominio con separadores repetidos (posible typo-squatting)")
		score += 6

	score = min(score, 100)
	return {
		"score": score,
		"risk_level": _risk_level(score),
		"findings": findings,
		"details": {
			"sender_domain": sender_domain,
			"reply_to_domain": reply_to_domain,
			"suspicious_finding_count": len(findings),
		},
	}
