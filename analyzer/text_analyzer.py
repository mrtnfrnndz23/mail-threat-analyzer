from __future__ import annotations

import re


PHISHING_TERMS = {
	"verifica",
	"verifique",
	"verify",
	"password",
	"contrasena",
	"credenciales",
	"account",
	"cuenta",
	"suspendida",
	"bloqueada",
	"security alert",
	"alerta de seguridad",
	"unusual activity",
	"actividad inusual",
	"click aqui",
	"click here",
	"inicie sesion",
	"login",
}

URGENCY_TERMS = {
	"urgente",
	"inmediato",
	"hoy",
	"ahora",
	"24 horas",
	"final notice",
	"ultimo aviso",
}

PAYMENT_TERMS = {
	"factura",
	"invoice",
	"transferencia",
	"wire",
	"payment",
	"pago",
	"iban",
	"swift",
}


def _risk_level(score: int) -> str:
	if score >= 75:
		return "critical"
	if score >= 50:
		return "high"
	if score >= 25:
		return "medium"
	return "low"


def _normalize(text: str) -> str:
	return re.sub(r"\s+", " ", text.lower()).strip()


def _match_terms(text: str, terms: set[str]) -> list[str]:
	hits = [term for term in terms if term in text]
	return sorted(set(hits))


def analyze_text(subject: str, body: str) -> dict:
	"""Analyze message text for social-engineering phishing indicators."""
	findings: list[str] = []
	score = 0

	normalized_subject = _normalize(subject or "")
	normalized_body = _normalize(body or "")
	full_text = f"{normalized_subject} {normalized_body}".strip()

	phishing_hits = _match_terms(full_text, PHISHING_TERMS)
	urgency_hits = _match_terms(full_text, URGENCY_TERMS)
	payment_hits = _match_terms(full_text, PAYMENT_TERMS)

	if phishing_hits:
		findings.append("Terminos de phishing detectados: " + ", ".join(phishing_hits))
		score += min(30, 4 * len(phishing_hits))

	if urgency_hits:
		findings.append("Lenguaje de urgencia detectado: " + ", ".join(urgency_hits))
		score += min(20, 4 * len(urgency_hits))

	if payment_hits:
		findings.append("Terminos financieros sensibles: " + ", ".join(payment_hits))
		score += min(20, 4 * len(payment_hits))

	if re.search(r"\b(?:codigo|code)\s*(?:otp|2fa|verificacion|verification)\b", full_text):
		findings.append("Solicitud de codigo OTP/2FA")
		score += 15

	if re.search(r"\b(?:usuario|user|correo|email)\b.{0,24}\b(?:contrasena|password)\b", full_text):
		findings.append("Solicitud explicita de credenciales")
		score += 20

	exclamations = (subject or "").count("!") + (body or "").count("!")
	if exclamations >= 5:
		findings.append("Uso excesivo de signos de exclamacion")
		score += 5

	if len((body or "").strip()) < 20 and len((subject or "").strip()) > 0:
		findings.append("Mensaje demasiado breve con contexto limitado")
		score += 5

	score = min(score, 100)
	return {
		"score": score,
		"risk_level": _risk_level(score),
		"findings": findings,
		"details": {
			"subject_length": len(subject or ""),
			"body_length": len(body or ""),
			"suspicious_finding_count": len(findings),
		},
	}
