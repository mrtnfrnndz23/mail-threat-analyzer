from __future__ import annotations

import ipaddress
import re
from typing import Iterable
from urllib.parse import urlparse


SUSPICIOUS_TLDS = {
	"zip",
	"mov",
	"click",
	"country",
	"gq",
	"tk",
	"top",
	"work",
}

URL_SHORTENERS = {
	"bit.ly",
	"tinyurl.com",
	"t.co",
	"goo.gl",
	"is.gd",
	"ow.ly",
	"buff.ly",
	"rebrand.ly",
}

SUSPICIOUS_URL_TERMS = {
	"login",
	"verify",
	"password",
	"secure",
	"update",
	"confirm",
	"account",
	"bank",
	"invoice",
}


def _risk_level(score: int) -> str:
	if score >= 75:
		return "critical"
	if score >= 50:
		return "high"
	if score >= 25:
		return "medium"
	return "low"


def _is_ip_hostname(hostname: str) -> bool:
	try:
		ipaddress.ip_address(hostname)
		return True
	except ValueError:
		return False


def _base_domain_parts(hostname: str) -> list[str]:
	return [part for part in hostname.lower().split(".") if part]


def analyze_links(links: Iterable[str]) -> dict:
	"""Analyze links for common phishing indicators.

	Returns a dict with score (0-100), risk_level and findings.
	"""
	findings: list[str] = []
	score = 0
	total_links = 0

	for raw_link in links:
		if not raw_link:
			continue
		total_links += 1
		link = raw_link.strip()
		parsed = urlparse(link)

		if parsed.scheme not in {"http", "https"}:
			findings.append(f"Scheme inusual en link: {link}")
			score += 8

		if parsed.scheme == "http":
			findings.append(f"Link sin HTTPS: {link}")
			score += 10

		hostname = (parsed.hostname or "").lower()
		if not hostname:
			findings.append(f"Link con host invalido: {link}")
			score += 15
			continue

		if _is_ip_hostname(hostname):
			findings.append(f"Link usa direccion IP en lugar de dominio: {link}")
			score += 15

		if hostname.startswith("xn--") or ".xn--" in hostname:
			findings.append(f"Posible homografo/punycode detectado: {hostname}")
			score += 20

		if hostname in URL_SHORTENERS:
			findings.append(f"Uso de acortador de URL: {hostname}")
			score += 10

		parts = _base_domain_parts(hostname)
		if len(parts) >= 3:
			findings.append(f"Dominio con multiples subdominios: {hostname}")
			score += 5

		if parts:
			tld = parts[-1]
			if tld in SUSPICIOUS_TLDS:
				findings.append(f"TLD de alto riesgo detectado: .{tld}")
				score += 12

		full_path = f"{parsed.path} {parsed.query}".lower()
		term_hits = [term for term in SUSPICIOUS_URL_TERMS if term in full_path]
		if term_hits:
			findings.append(
				"URL contiene terminos sensibles: " + ", ".join(sorted(term_hits))
			)
			score += min(12, 3 * len(term_hits))

		if "@" in link:
			findings.append(f"URL contiene '@' (posible ofuscacion): {link}")
			score += 12

		if re.search(r"%[0-9a-fA-F]{2}", link):
			findings.append(f"URL contiene encoding (posible ofuscacion): {link}")
			score += 4

	if total_links >= 5:
		findings.append("Cantidad inusual de links en el mensaje")
		score += 5

	score = min(score, 100)
	return {
		"score": score,
		"risk_level": _risk_level(score),
		"findings": findings,
		"details": {
			"total_links": total_links,
			"suspicious_finding_count": len(findings),
		},
	}
