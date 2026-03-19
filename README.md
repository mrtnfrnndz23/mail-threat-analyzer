# Mail Threat Analyzer 🛡️

A Python-based service that analyzes suspicious emails and returns a risk score based on multiple heuristics.

## 🚀 Features

- Email parsing
- Suspicious link detection
- Domain analysis
- Attachment inspection
- Phishing keyword detection
- Risk scoring system

## 🧱 Tech Stack

- Python
- FastAPI
- Docker
- MailHog

## 📦 Architecture

Mail → Processor → Analyzer → Risk Score → Response

## ▶️ How to run

```bash
docker-compose up
