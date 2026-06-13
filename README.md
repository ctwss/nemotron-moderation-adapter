# Nemotron Moderation Adapter

OpenAI-compatible moderation API adapter backed by NVIDIA Nemotron Content Safety.

This service exposes `POST /v1/moderations`, accepts OpenAI-style moderation input, forwards the content to NVIDIA's `nvidia/nemotron-3.5-content-safety` chat completion endpoint, parses the safety result, and maps Aegis/Nemotron categories into OpenAI moderation response fields.

## Features

- OpenAI-compatible `POST /v1/moderations` response shape
- Text and `image_url` content part support
- Optional assistant `output` moderation context
- NVIDIA API key passthrough from `Authorization: Bearer ...`
- Optional fallback API keys from environment variables
- Round-robin fallback key selection when multiple keys are configured
- Health endpoint at `GET /health`
- Docker and Docker Compose support

## Requirements

- Go 1.23+
- NVIDIA API key with access to `nvidia/nemotron-3.5-content-safety`
- Docker, optional

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `NVIDIA_API_KEY` | empty | Single fallback NVIDIA API key. Used when the incoming request has no bearer token. |
| `NVIDIA_API_KEYS` | empty | Comma-separated fallback NVIDIA API keys. Takes precedence over `NVIDIA_API_KEY`. |
| `NVIDIA_BASE_URL` | `https://integrate.api.nvidia.com` | NVIDIA API base URL. |
| `LISTEN_PORT` | `8080` | HTTP listen port. |
| `TIMEOUT_SEC` | `30` | Upstream request timeout in seconds. |

Incoming bearer tokens are preferred. If a request includes:

```http
Authorization: Bearer nvapi-...
```

the adapter forwards that key to NVIDIA. If no bearer token is provided, the service uses `NVIDIA_API_KEYS` or `NVIDIA_API_KEY`.

## Run Locally

```bash
export NVIDIA_API_KEY="nvapi-your-key"
go run ./cmd/server
```

On Windows PowerShell:

```powershell
$env:NVIDIA_API_KEY = "nvapi-your-key"
go run ./cmd/server
```

Check health:

```bash
curl http://127.0.0.1:8080/health
```

## API Usage

Moderate a string:

```bash
curl http://127.0.0.1:8080/v1/moderations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer nvapi-your-key" \
  -d '{"model":"omni-moderation-latest","input":"I want to hurt someone."}'
```

Moderate multiple strings:

```bash
curl http://127.0.0.1:8080/v1/moderations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer nvapi-your-key" \
  -d '{"input":["hello","threatening text here"]}'
```

Moderate content parts:

```bash
curl http://127.0.0.1:8080/v1/moderations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer nvapi-your-key" \
  -d '{
    "input": [
      {"type":"text","text":"Review this image"},
      {"type":"image_url","image_url":{"url":"https://example.com/image.png"}}
    ]
  }'
```

Example response:

```json
{
  "id": "modr-...",
  "model": "omni-moderation-latest",
  "results": [
    {
      "flagged": true,
      "categories": {
        "violence": true
      },
      "category_scores": {
        "violence": 0.99
      },
      "category_applied_input_types": {
        "violence": ["text"]
      }
    }
  ]
}
```

The actual response includes all supported OpenAI moderation categories.

## Docker

Build and run:

```bash
docker build -t nemotron-moderation-adapter:latest .
docker run --rm -p 8080:8080 -e NVIDIA_API_KEY="nvapi-your-key" nemotron-moderation-adapter:latest
```

Or use Docker Compose:

```bash
NVIDIA_API_KEY="nvapi-your-key" docker compose up --build
```

## Development

Run tests:

```bash
go test ./...
```

Build the binary:

```bash
make build
```

Build the Docker image:

```bash
make docker-build
```

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Returns `{"status":"ok"}`. |
| `POST` | `/v1/moderations` | OpenAI-compatible moderation endpoint. |

## Notes

Category mapping is implemented in `internal/adapter/mapper.go`. Strong mappings are mapped directly to OpenAI moderation categories; weak or unknown mappings are included in request logs for auditability.
