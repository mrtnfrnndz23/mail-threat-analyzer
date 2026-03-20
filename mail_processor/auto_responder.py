from __future__ import annotations

import hashlib
import imaplib
import json
import os
import re
import smtplib
import time
from html import escape
from pathlib import Path
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from typing import Any

from analyzer.engine import analyze_email_payload


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _str_env(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip()
    return value or default


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def _strip_html(html: str) -> str:
    # Fallback simple HTML-to-text for messages without plain-text parts.
    text = re.sub(r"<style.*?>.*?</style>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<script.*?>.*?</script>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _extract_body_and_attachments(message: EmailMessage) -> tuple[str, list[dict[str, Any]]]:
    body_candidates: list[str] = []
    html_candidates: list[str] = []
    attachments: list[dict[str, Any]] = []

    for part in message.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        content_type = (part.get_content_type() or "").lower()

        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                {
                    "filename": filename or "",
                    "size": len(payload),
                    "mime_type": content_type,
                }
            )
            continue

        try:
            content = part.get_content()
        except Exception:
            raw_bytes = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            content = raw_bytes.decode(charset, errors="replace")

        if content_type == "text/plain":
            body_candidates.append(str(content).strip())
        elif content_type == "text/html":
            html_candidates.append(_strip_html(str(content)))

    if body_candidates:
        body = "\n\n".join(item for item in body_candidates if item)
    else:
        body = "\n\n".join(item for item in html_candidates if item)

    return body.strip(), attachments


def _build_analysis_payload(message: EmailMessage) -> tuple[dict[str, Any], str]:
    from_name, from_email = parseaddr(message.get("From", ""))
    reply_to_name, reply_to_email = parseaddr(message.get("Reply-To", ""))
    _ = reply_to_name

    subject = str(message.get("Subject", "")).strip()
    body, attachments = _extract_body_and_attachments(message)

    payload = {
        "from_email": from_email,
        "reply_to_email": reply_to_email or None,
        "display_name": from_name or None,
        "subject": subject,
        "body": body,
        "attachments": attachments,
    }
    return payload, from_email


def _format_analysis_email_text(subject: str, analysis: dict[str, Any]) -> str:
    findings = analysis.get("findings", [])
    top_findings = findings[:20]

    lines = [
        "Hola,",
        "",
        "Tu correo reenviado fue analizado automaticamente.",
        "",
        f"Asunto analizado: {subject}",
        f"Riesgo: {analysis['risk_level']} ({analysis['risk_score']}/100)",
        "",
        "Hallazgos principales:",
    ]

    if top_findings:
        for finding in top_findings:
            lines.append(f"- {finding}")
    else:
        lines.append("- No se detectaron indicadores relevantes.")

    lines.extend(
        [
            "",
            "Este resultado es heuristico y puede tener falsos positivos/negativos.",
            "",
            "Mail Threat Analyzer",
        ]
    )
    return "\n".join(lines)


def _format_analysis_email_html(subject: str, analysis: dict[str, Any]) -> str:
    findings = analysis.get("findings", [])
    top_findings = findings[:20]
    list_items = "".join(f"<li>{escape(item)}</li>" for item in top_findings)
    if not list_items:
        list_items = "<li>No se detectaron indicadores relevantes.</li>"

    return (
        "<html><body style='font-family:Arial,sans-serif;'>"
        "<h2>Resultado de analisis de correo</h2>"
        f"<p><strong>Asunto analizado:</strong> {escape(subject or '(sin asunto)')}</p>"
        f"<p><strong>Riesgo:</strong> {escape(analysis['risk_level'])} "
        f"({analysis['risk_score']}/100)</p>"
        "<h3>Hallazgos principales</h3>"
        f"<ul>{list_items}</ul>"
        "<p style='color:#555;'>Este resultado es heuristico y puede tener falsos "
        "positivos/negativos.</p>"
        "<p>Mail Threat Analyzer</p>"
        "</body></html>"
    )


def _message_key(message: EmailMessage, raw_email: bytes) -> str:
    message_id = str(message.get("Message-ID", "")).strip().lower()
    if message_id:
        return f"mid:{message_id}"
    digest = hashlib.sha256(raw_email).hexdigest()
    return f"sha256:{digest}"


def _load_processed_keys(state_file: Path) -> set[str]:
    if not state_file.exists():
        return set()

    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return set()

    keys = data.get("processed_keys", [])
    if not isinstance(keys, list):
        return set()
    return {str(item) for item in keys if str(item).strip()}


def _save_processed_keys(state_file: Path, processed_keys: set[str], max_items: int) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(processed_keys)
    if len(ordered) > max_items:
        ordered = ordered[-max_items:]
    data = {"processed_keys": ordered}
    state_file.write_text(json.dumps(data, ensure_ascii=True, indent=2), encoding="utf-8")


def _send_response_mail(
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    smtp_use_ssl: bool,
    to_email: str,
    original_subject: str,
    text_body: str,
    html_body: str,
) -> None:
    message = EmailMessage()
    message["From"] = smtp_user
    message["To"] = to_email
    message["Subject"] = f"[Mail Threat Analyzer] Resultado: {original_subject or '(sin asunto)'}"
    message.set_content(text_body)
    message.add_alternative(html_body, subtype="html")

    if smtp_use_ssl:
        with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=30) as server:
            server.login(smtp_user, smtp_password)
            server.send_message(message)
    else:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(message)


def _process_unseen_messages() -> None:
    smtp_host = _required_env("SMTP_HOST")
    smtp_port = _int_env("SMTP_PORT", 465)
    smtp_user = _required_env("SMTP_USER")
    smtp_password = _required_env("SMTP_PASSWORD")
    smtp_use_ssl = _bool_env("SMTP_USE_SSL", True)

    imap_host = _required_env("IMAP_HOST")
    imap_port = _int_env("IMAP_PORT", 993)
    imap_user = os.getenv("IMAP_USER", smtp_user).strip() or smtp_user
    imap_password = os.getenv("IMAP_PASSWORD", smtp_password).strip() or smtp_password
    imap_use_ssl = _bool_env("IMAP_USE_SSL", True)
    imap_folder = _str_env("IMAP_FOLDER", "INBOX")
    search_criteria = _str_env("IMAP_SEARCH_CRITERIA", "UNSEEN")

    state_file = Path(_str_env("WORKER_STATE_FILE", "/app/data/processed_ids.json"))
    max_processed = _int_env("MAX_PROCESSED_IDS", 5000)
    processed_keys = _load_processed_keys(state_file)

    if imap_use_ssl:
        client = imaplib.IMAP4_SSL(imap_host, imap_port)
    else:
        client = imaplib.IMAP4(imap_host, imap_port)

    try:
        client.login(imap_user, imap_password)
        client.select(imap_folder)

        status, data = client.search(None, search_criteria)
        if status != "OK":
            return

        message_ids = data[0].split()
        for message_id in message_ids:
            status, fetched = client.fetch(message_id, "(RFC822)")
            if status != "OK" or not fetched or not fetched[0]:
                continue

            raw_email = fetched[0][1]
            message = BytesParser(policy=policy.default).parsebytes(raw_email)
            key = _message_key(message, raw_email)

            if key in processed_keys:
                client.store(message_id, "+FLAGS", "\\Seen")
                continue

            payload, sender_email = _build_analysis_payload(message)

            # Prevent auto-reply loops if mailbox receives its own responses.
            subject = str(payload.get("subject", ""))
            if sender_email.lower() == smtp_user.lower() or subject.startswith("[Mail Threat Analyzer]"):
                client.store(message_id, "+FLAGS", "\\Seen")
                processed_keys.add(key)
                _save_processed_keys(state_file, processed_keys, max_processed)
                continue

            analysis = analyze_email_payload(payload)
            response_body_text = _format_analysis_email_text(subject=subject, analysis=analysis)
            response_body_html = _format_analysis_email_html(subject=subject, analysis=analysis)

            if sender_email:
                _send_response_mail(
                    smtp_host=smtp_host,
                    smtp_port=smtp_port,
                    smtp_user=smtp_user,
                    smtp_password=smtp_password,
                    smtp_use_ssl=smtp_use_ssl,
                    to_email=sender_email,
                    original_subject=subject,
                    text_body=response_body_text,
                    html_body=response_body_html,
                )

            client.store(message_id, "+FLAGS", "\\Seen")
            processed_keys.add(key)
            _save_processed_keys(state_file, processed_keys, max_processed)
    finally:
        try:
            client.close()
        except Exception:
            pass
        client.logout()


def run_forever() -> None:
    interval = _int_env("MAIL_POLL_INTERVAL_SECONDS", 30)
    while True:
        try:
            _process_unseen_messages()
        except Exception as exc:
            print(f"[auto_responder] Error: {exc}")
        time.sleep(max(5, interval))


if __name__ == "__main__":
    run_forever()
