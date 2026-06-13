# Nemotron Moderation Adapter

[中文](#中文) | [English](#english)

## 中文

基于 NVIDIA Nemotron Content Safety 的 OpenAI 兼容 Moderation API 适配器。

本服务提供 `POST /v1/moderations` 接口，接收 OpenAI 风格的内容审核请求，将内容转发到 NVIDIA `nvidia/nemotron-3.5-content-safety` chat completion 接口，解析安全审核结果，并把 Aegis/Nemotron 分类映射为 OpenAI Moderation 响应字段。

### 功能特性

- OpenAI 兼容的 `POST /v1/moderations` 响应结构
- 支持文本和 `image_url` content part
- 支持可选的 assistant `output` 上下文审核
- 支持从 `Authorization: Bearer ...` 透传 NVIDIA API Key
- 支持通过环境变量配置备用 NVIDIA API Key
- 配置多个备用 Key 时支持轮询选择
- 健康检查接口：`GET /health`
- 支持 Docker 和 Docker Compose

### 环境要求

- Go 1.23+
- 可访问 `nvidia/nemotron-3.5-content-safety` 的 NVIDIA API Key
- Docker，可选

### 配置

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `NVIDIA_API_KEY` | 空 | 单个备用 NVIDIA API Key。当请求没有 bearer token 时使用。 |
| `NVIDIA_API_KEYS` | 空 | 逗号分隔的多个备用 NVIDIA API Key。优先级高于 `NVIDIA_API_KEY`。 |
| `NVIDIA_BASE_URL` | `https://integrate.api.nvidia.com` | NVIDIA API Base URL。 |
| `LISTEN_PORT` | `8080` | HTTP 监听端口。 |
| `TIMEOUT_SEC` | `30` | 上游请求超时时间，单位秒。 |

服务优先使用请求中的 bearer token。如果请求包含：

```http
Authorization: Bearer nvapi-...
```

适配器会把该 Key 转发给 NVIDIA。如果请求没有 bearer token，则使用 `NVIDIA_API_KEYS` 或 `NVIDIA_API_KEY`。

### 本地运行

```bash
export NVIDIA_API_KEY="nvapi-your-key"
go run ./cmd/server
```

Windows PowerShell：

```powershell
$env:NVIDIA_API_KEY = "nvapi-your-key"
go run ./cmd/server
```

检查健康状态：

```bash
curl http://127.0.0.1:8080/health
```

### API 用法

审核单条文本：

```bash
curl http://127.0.0.1:8080/v1/moderations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer nvapi-your-key" \
  -d '{"model":"omni-moderation-latest","input":"I want to hurt someone."}'
```

审核多条文本：

```bash
curl http://127.0.0.1:8080/v1/moderations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer nvapi-your-key" \
  -d '{"input":["hello","threatening text here"]}'
```

审核 content parts：

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

响应示例：

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

实际响应会包含所有支持的 OpenAI moderation categories。

### Docker

构建并运行：

```bash
docker build -t nemotron-moderation-adapter:latest .
docker run --rm -p 8080:8080 -e NVIDIA_API_KEY="nvapi-your-key" nemotron-moderation-adapter:latest
```

或使用 Docker Compose：

```bash
NVIDIA_API_KEY="nvapi-your-key" docker compose up --build
```

### 开发

运行测试：

```bash
go test ./...
```

构建二进制文件：

```bash
make build
```

构建 Docker 镜像：

```bash
make docker-build
```

### 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/health` | 返回 `{"status":"ok"}`。 |
| `POST` | `/v1/moderations` | OpenAI 兼容的内容审核接口。 |

### 说明

分类映射逻辑位于 `internal/adapter/mapper.go`。强映射会直接映射到 OpenAI moderation categories；弱映射或未知分类会写入请求日志，便于审计。

## English

OpenAI-compatible moderation API adapter backed by NVIDIA Nemotron Content Safety.

This service exposes `POST /v1/moderations`, accepts OpenAI-style moderation input, forwards the content to NVIDIA's `nvidia/nemotron-3.5-content-safety` chat completion endpoint, parses the safety result, and maps Aegis/Nemotron categories into OpenAI moderation response fields.

### Features

- OpenAI-compatible `POST /v1/moderations` response shape
- Text and `image_url` content part support
- Optional assistant `output` moderation context
- NVIDIA API key passthrough from `Authorization: Bearer ...`
- Optional fallback API keys from environment variables
- Round-robin fallback key selection when multiple keys are configured
- Health endpoint at `GET /health`
- Docker and Docker Compose support

### Requirements

- Go 1.23+
- NVIDIA API key with access to `nvidia/nemotron-3.5-content-safety`
- Docker, optional

### Configuration

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

### Run Locally

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

### API Usage

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

### Docker

Build and run:

```bash
docker build -t nemotron-moderation-adapter:latest .
docker run --rm -p 8080:8080 -e NVIDIA_API_KEY="nvapi-your-key" nemotron-moderation-adapter:latest
```

Or use Docker Compose:

```bash
NVIDIA_API_KEY="nvapi-your-key" docker compose up --build
```

### Development

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

### Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Returns `{"status":"ok"}`. |
| `POST` | `/v1/moderations` | OpenAI-compatible moderation endpoint. |

### Notes

Category mapping is implemented in `internal/adapter/mapper.go`. Strong mappings are mapped directly to OpenAI moderation categories; weak or unknown mappings are included in request logs for auditability.
