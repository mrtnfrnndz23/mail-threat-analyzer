from __future__ import annotations

from typing import Any, Mapping, Sequence


HIGH_RISK_EXTENSIONS = {
	".exe",
	".msi",
	".bat",
	".cmd",
	".js",
	".vbs",
	".scr",
	".ps1",
	".jar",
}

MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso"}


def _risk_level(score: int) -> str:
	if score >= 75:
		return "critical"
	if score >= 50:
		return "high"
	if score >= 25:
		return "medium"
	return "low"


def _extension(filename: str) -> str:
	if "." not in filename:
		return ""
	return "." + filename.lower().rsplit(".", 1)[-1]


def analyze_attachments(attachments: Sequence[Mapping[str, Any]]) -> dict:
	"""Analyze attachment metadata for dangerous patterns.

	Expected attachment keys (if available): filename, size, mime_type.
	"""
	findings: list[str] = []
	score = 0

	for attachment in attachments:
		filename = str(attachment.get("filename", "")).strip()
		size = int(attachment.get("size", 0) or 0)
		mime_type = str(attachment.get("mime_type", "")).lower()

		if not filename:
			findings.append("Adjunto sin nombre detectado")
			score += 10
			continue

		ext = _extension(filename)

		if ext in HIGH_RISK_EXTENSIONS:
			findings.append(f"Adjunto ejecutable/script de alto riesgo: {filename}")
			score += 35

		if ext in MACRO_EXTENSIONS:
			findings.append(f"Documento con macros potenciales: {filename}")
			score += 20

		if ext in ARCHIVE_EXTENSIONS:
			findings.append(f"Archivo comprimido adjunto (posible evasivo): {filename}")
			score += 10

		pieces = filename.lower().split(".")
		if len(pieces) >= 3:
			findings.append(f"Doble extension detectada: {filename}")
			score += 15

		if size > 20 * 1024 * 1024:
			findings.append(f"Adjunto muy grande ({size} bytes): {filename}")
			score += 8

		if "application/octet-stream" in mime_type:
			findings.append(f"MIME generico en adjunto: {filename}")
			score += 8

	if len(attachments) >= 5:
		findings.append("Cantidad inusual de adjuntos")
		score += 8

	score = min(score, 100)
	return {
		"score": score,
		"risk_level": _risk_level(score),
		"findings": findings,
		"details": {
			"total_attachments": len(attachments),
			"suspicious_finding_count": len(findings),
		},
	}
