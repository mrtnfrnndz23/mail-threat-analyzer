from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from analyzer.engine import analyze_email_payload


class AttachmentInput(BaseModel):
	filename: str = ""
	size: int = 0
	mime_type: str = ""


class EmailAnalyzeRequest(BaseModel):
	from_email: str = Field(..., description="Email address of sender")
	reply_to_email: str | None = Field(default=None)
	display_name: str | None = Field(default=None)
	subject: str = ""
	body: str = ""
	links: list[str] | None = None
	attachments: list[AttachmentInput] | None = None


class AnalyzeResponse(BaseModel):
	risk_score: int
	risk_level: str
	findings: list[str]
	modules: dict[str, Any]


app = FastAPI(
	title="Mail Threat Analyzer",
	description="API para analisis de riesgo de phishing en correos.",
	version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
	return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_email(request: EmailAnalyzeRequest) -> AnalyzeResponse:
	result = analyze_email_payload(request.model_dump())

	return AnalyzeResponse(
		risk_score=result["risk_score"],
		risk_level=result["risk_level"],
		findings=result["findings"],
		modules=result["modules"],
	)
