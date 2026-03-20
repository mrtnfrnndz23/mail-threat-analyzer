# Agent.md - Contexto operativo del proyecto

## 1) Objetivo
Construir un servicio que analice correos sospechosos y devuelva un score de riesgo de phishing con explicaciones por modulo.

Modulos de analisis:
- links
- dominio/remitente
- adjuntos
- texto

## 2) Estado actual (20-Mar-2026)
El MVP tecnico base ya esta implementado.

Implementado:
- API FastAPI con endpoints `GET /health` y `POST /analyze`.
- Parser de payload en `mail_processor/parser.py`.
- Cuatro analizadores en `analyzer/`.
- Agregacion de score global ponderado.
- Motor de analisis compartido en `analyzer/engine.py`.
- Worker de auto-respuesta por correo en `mail_processor/auto_responder.py`.
- Deduplicacion persistente por Message-ID/hash para evitar reprocesos.
- Respuesta multipart (texto + HTML) para mejor compatibilidad de clientes.
- Dockerfile funcional para la API.
- docker-compose con servicios `api` y `mail_worker`.
- Volumen Docker para persistir estado del worker entre reinicios.
- Uso de SMTP real por variables de entorno en `.env` (sin MailHog).

Pendiente principal:
- Pruebas automatizadas (unitarias e integracion).
- Endurecer validaciones y tunear pesos/reglas.
- Mejorar estrategia de procesado para evitar duplicados y almacenar historico.

## 3) Arquitectura actual
Flujo actual:
1. `POST /analyze` recibe payload JSON del correo.
2. `mail_processor/parser.py` normaliza campos y extrae links/adjuntos.
3. `analyzer/*.py` genera score + findings por modulo.
4. `api/main.py` agrega resultados con pesos y devuelve respuesta consolidada.

Flujo automatico por correo:
1. `mail_worker` consulta IMAP (correos no leidos).
2. Parsea correo recibido (subject/body/adjuntos/remitente).
3. Ejecuta el mismo motor de analisis (`analyzer/engine.py`).
4. Responde por SMTP al remitente con score y hallazgos.
5. Guarda identificadores procesados para evitar respuestas duplicadas.

Respuesta actual:
- `risk_score`
- `risk_level`
- `findings`
- `modules` (resultado por analizador)

## 4) Estructura de carpetas
- `api/`: API y orquestacion.
- `mail_processor/`: parser y normalizacion.
- `analyzer/`: reglas heuristicas por tipo de evidencia.
- `docker/`: imagen de la API.
- `docker-compose.yml`: servicio local de API.
- `.env`: configuracion SMTP real (no versionada).
- `requirements.txt`: dependencias Python.

## 5) Variables de entorno de correo
Servidor real configurado para SMTP/IMAP/POP con SSL.

Variables actuales esperadas:
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASSWORD`
- `SMTP_USE_SSL`
- `IMAP_HOST`
- `IMAP_PORT`
- `IMAP_USE_SSL`
- `POP3_HOST`
- `POP3_PORT`
- `POP3_USE_SSL`

Nota:
- `.env` esta incluido en `.gitignore` para evitar credenciales hardcodeadas/versionadas.

## 6) Ejecucion
Local con Docker Compose:
- `docker-compose up --build`

API esperada:
- `http://localhost:8000`
- `http://localhost:8000/docs`

Worker esperado:
- se ejecuta en segundo contenedor y procesa periodicamente `UNSEEN` en `IMAP_FOLDER`.
- usa `WORKER_STATE_FILE` para recordar correos ya procesados.

Local sin Docker (debug):
- `uvicorn api.main:app --reload --host 0.0.0.0 --port 8000`

## 7) Convenciones para agentes
- Mantener analizadores como funciones puras y testeables.
- Evitar logica de negocio pesada dentro de rutas FastAPI.
- Mantener contrato de entrada/salida estable en `POST /analyze`.
- Al agregar reglas nuevas, incluir trazabilidad en `findings`.
- Si se modifican pesos de riesgo, documentar el racional.

## 8) Backlog recomendado (siguiente etapa)
1. Crear suite de pruebas (`pytest`) para parser y analyzers.
2. Agregar pruebas de integracion para `POST /analyze`.
3. Ajustar calibracion de score con casos reales.
4. Agregar autenticacion basica a la API si se expone fuera de red interna.
5. Registrar logs estructurados por analisis para auditoria.

## 9) Definicion de listo (MVP utilizable)
- Endpoint `/analyze` estable y documentado.
- Score explicable con findings por modulo.
- Ejecucion reproducible con `docker-compose up --build`.
- Credenciales fuera del codigo (via `.env`).
- Pruebas minimas automatizadas en verde.
