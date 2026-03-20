# Mail Threat Analyzer 🛡️

Servicio basado en Python que analiza correos sospechosos y devuelve un puntaje de riesgo usando multiples heuristicas.

## 🚀 Caracteristicas

- Parseo de correo
- Deteccion de links sospechosos
- Analisis de dominio
- Inspeccion de adjuntos
- Deteccion de palabras clave de phishing
- Sistema de puntaje de riesgo

## 🧱 Stack tecnologico

- Python
- FastAPI
- Docker
- SMTP real

## 📦 Arquitectura

Correo → Procesador → Analizador → Puntaje de riesgo → Respuesta

## ▶️ Como ejecutar

Configura estas variables de entorno para usar tu servidor SMTP real:

```bash
SMTP_HOST=smtp.tu-proveedor.com
SMTP_PORT=465
SMTP_USER=tu_usuario
SMTP_PASSWORD=tu_password
SMTP_USE_SSL=true
IMAP_HOST=c1740750.ferozo.com
IMAP_PORT=993
IMAP_USE_SSL=true
IMAP_USER=tu_usuario
IMAP_PASSWORD=tu_password
IMAP_FOLDER=INBOX
IMAP_SEARCH_CRITERIA=UNSEEN
MAIL_POLL_INTERVAL_SECONDS=30
WORKER_STATE_FILE=/app/data/processed_ids.json
MAX_PROCESSED_IDS=5000
```

Luego levanta el entorno:

```bash
docker-compose up
```

API disponible en:

```bash
http://localhost:8000
```

Flujo automatico por correo (worker):
- Reenvias un correo sospechoso a la cuenta configurada en .env.
- El servicio mail_worker revisa IMAP (no leidos), analiza el correo y responde por SMTP.
- La respuesta llega al remitente del correo reenviado con puntaje y hallazgos.
- El worker guarda IDs procesados en un volumen Docker para evitar reprocesar correos tras reinicios.

