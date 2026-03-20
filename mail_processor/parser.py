from __future__ import annotations

import re
from typing import Any


LINK_PATTERN = re.compile(r"https?://[^\s<>'\"]+")


def extract_links(text: str) -> list[str]:
	if not text:
		return []
	return [match.group(0).rstrip(".,;:)") for match in LINK_PATTERN.finditer(text)]


def normalize_attachments(attachments: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
	if not attachments:
		return []

	normalized: list[dict[str, Any]] = []
	for item in attachments:
		filename = str(item.get("filename", "")).strip()
		size_raw = item.get("size", 0)
		mime_type = str(item.get("mime_type", "")).strip().lower()
		try:
			size = int(size_raw or 0)
		except (TypeError, ValueError):
			size = 0

		normalized.append(
			{
				"filename": filename,
				"size": max(size, 0),
				"mime_type": mime_type,
			}
		)
	return normalized


def parse_email_payload(payload: dict[str, Any]) -> dict[str, Any]:
	"""Normalize email payload to a single schema used by analyzers."""
	sender = str(payload.get("from_email", "")).strip()
	reply_to = str(payload.get("reply_to_email", "")).strip() or None
	display_name = str(payload.get("display_name", "")).strip() or None
	subject = str(payload.get("subject", "")).strip()
	body = str(payload.get("body", ""))

	links = payload.get("links")
	if links is None:
		links = extract_links(f"{subject}\n{body}")
	else:
		links = [str(link).strip() for link in links if str(link).strip()]

	attachments = normalize_attachments(payload.get("attachments"))

	return {
		"from_email": sender,
		"reply_to_email": reply_to,
		"display_name": display_name,
		"subject": subject,
		"body": body,
		"links": links,
		"attachments": attachments,
	}
