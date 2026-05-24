# VPS-Guard Agent — Central Platform API Contract

**Version**: 0.2.0  
**Status**: Draft  
**Last Updated**: 2026-05-24

> This document defines the HTTP API contract between the VPS-Guard **Agent** and the **Central Platform**.  
> The Agent is the consumer; the Platform is the provider.  
> Both sides can be developed independently as long as this contract is honoured.

---

## 1. Overview

The Agent periodically pulls threat intelligence from the Central Platform via a RESTful HTTPS endpoint.  
The Platform returns a list of threat items — IP addresses with associated metadata — that the Agent merges into its local scoring engine.

The contract consists of **two endpoints**:

| Endpoint | Direction | Description |
|----------|-----------|-------------|
| `GET /api/v1/threat-feed` | Agent → Platform (pull) | Fetch threat items |
| `POST /api/v1/report` | Agent → Platform (push) | Report local observations (optional) |

---

## 2. Authentication

All requests **MUST** include a `Bearer` token in the `Authorization` header:

```
Authorization: Bearer <platform_api_token>
```

- Token is configured in `central_feed.api_token` in `config.yaml`
- Token is static per-agent (future: per-agent JWT)
- Platform **MUST** return `401 Unauthorized` for invalid tokens
- Platform **MUST** return `403 Forbidden` if the agent is not authorised for feed access

---

## 3. Endpoint: `GET /api/v1/threat-feed`

### 3.1 Request

**Query Parameters**:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `since` | ISO8601 | No | `-24h` | Only return items modified after this timestamp |
| `limit` | int | No | `1000` | Maximum items to return (max: 5000) |
| `min_confidence` | int | No | `0` | Minimum confidence filter (0-100) |
| `agent_id` | string | No | — | Unique agent identifier (for geo-targeted feeds) |

**Example**:
```
GET /api/v1/threat-feed?since=2026-05-23T00:00:00Z&limit=100&min_confidence=50
```

### 3.2 Response

**Status Codes**:
- `200 OK` — Success
- `401 Unauthorized` — Missing or invalid token
- `403 Forbidden` — Token valid but not authorised
- `429 Too Many Requests` — Rate limit exceeded
- `5xx` — Platform error (Agent will retry with backoff)

**Response Body** (JSON):

```json
{
  "feed": [
    {
      "ip": "185.220.101.X",
      "confidence": 92,
      "category": ["ssh_brute", "scanner"],
      "ttl_hours": 48,
      "sources": ["platform_honeypot", "honeypot_network"],
      "recommended_action": "block",
      "first_seen": "2026-05-20T10:30:00Z",
      "last_seen": "2026-05-23T08:15:00Z",
      "report_count": 15
    }
  ],
  "pagination": {
    "total": 1520,
    "returned": 100,
    "next_cursor": "2026-05-23T08:15:00Z"
  },
  "generated_at": "2026-05-24T06:00:00Z"
}
```

### 3.3 ThreatItem Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ip` | string | ✅ | IPv4 or IPv6 address |
| `confidence` | int | ✅ | 0-100. Confidence that this IP is malicious |
| `category` | string[] | ✅ | Attack categories (see below) |
| `ttl_hours` | int | ✅ | How long this intelligence is valid (1-720) |
| `sources` | string[] | ❌ | Source identifiers that reported this IP |
| `recommended_action` | string | ❌ | `block`, `quarantine`, or `monitor` (default: `monitor`) |
| `first_seen` | ISO8601 | ❌ | When the platform first observed this IP |
| `last_seen` | ISO8601 | ✅ | When the platform last observed this IP |
| `report_count` | int | ❌ | Number of independent reports |

### 3.4 Category Values

| Category | Description |
|----------|-------------|
| `ssh_brute` | SSH brute-force attempts |
| `scanner` | Port/service scanning |
| `botnet` | Botnet C2 or member |
| `malware` | Malware download/malicious payload |
| `phishing` | Phishing host |
| `dos` | Denial-of-service source |
| `spam` | Email spam source |
| `unknown` | Unclassified malicious activity |

### 3.5 Agent Behaviour

When the Agent receives the feed:

| Confidence | Agent Action |
|------------|--------------|
| ≥ 90 | Immediate block (24h) + notify |
| 60–89 | Quarantine (15m) + monitor |
| < 60 | Score boost only (weighted 15%) |

The Agent **never trusts the feed blindly**. Central feed contributes at most **15%** of the final score.

---

## 4. Endpoint: `POST /api/v1/report` (Optional)

### 4.1 Request

**Headers**:
```
Content-Type: application/json
Authorization: Bearer <platform_api_token>
```

**Request Body** (JSON):

```json
{
  "agent_id": "vps-nyc1-01",
  "agent_version": "0.2.0",
  "events": [
    {
      "ip": "185.220.101.X",
      "timestamp": "2026-05-24T05:30:00Z",
      "event_type": "ssh_failed_login",
      "username": "root",
      "port": 22,
      "local_score": 85,
      "verdict": "blocked",
      "trace_id": "b7f3a1c2-4d5e-4f6a-8b7c-9d0e1f2a3b4c"
    }
  ],
  "reported_at": "2026-05-24T06:00:00Z"
}
```

### 4.2 Response

- `202 Accepted` — Reports received (async processing)
- `429 Too Many Requests` — Slow down
- `413 Payload Too Large` — Batch too big (max 100 events)

### 4.3 ReportEvent Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ip` | string | ✅ | Attacker IP address |
| `timestamp` | ISO8601 | ✅ | When the event was observed |
| `event_type` | string | ✅ | `ssh_failed_login`, `invalid_user`, `port_scan`, `central_feed_match` |
| `username` | string | ❌ | Username attempted (SSH only) |
| `port` | int | ❌ | Destination port |
| `local_score` | int | ✅ | Agent's calculated score (0-100) |
| `verdict` | string | ✅ | `blocked`, `quarantined`, `monitored`, `ignored` |
| `trace_id` | string | ❌ | Agent's internal trace ID for correlation |

---

## 5. Error Responses

All errors follow a standard format:

```json
{
  "error": {
    "code": "rate_limit_exceeded",
    "message": "Too many requests. Try again in 30 seconds.",
    "retry_after_seconds": 30
  }
}
```

| HTTP Code | Error Code | Description |
|-----------|------------|-------------|
| 400 | `bad_request` | Invalid parameters |
| 401 | `unauthorized` | Missing/invalid token |
| 403 | `forbidden` | Not authorised |
| 404 | `not_found` | Endpoint not found |
| 429 | `rate_limit_exceeded` | Back off and retry |
| 500 | `internal_error` | Platform error |

---

## 6. Rate Limiting

| Endpoint | Limit | Window |
|----------|-------|--------|
| `GET /api/v1/threat-feed` | 60 requests | 1 minute |
| `POST /api/v1/report` | 120 requests | 1 minute |

Agent implements exponential backoff on `429`:
- Initial retry: 30s
- Max retry: 5min
- Jitter: ±25%

---

## 7. Versioning

- API version is embedded in the URL path: `/api/v1/`
- Breaking changes → new version (`/api/v2/`)
- Non-breaking additions (new fields) are allowed within the same version
- Unknown fields **MUST** be ignored by the Agent (forward compatibility)

---

## 8. Implementation Notes

### Agent Side (already implemented)
- `internal/api/pull_client.go` — HTTPS pull client with Bearer auth
- Configurable interval (default: 60s)
- Min confidence filter per `central_feed.min_confidence` in config
- Merges feed items into `internal/threat/cache.go` (SQLite with TTL)
- Handles `429` with exponential backoff

### Platform Side (to be implemented — Phase B)
- Must implement `GET /api/v1/threat-feed` per schema above
- Should implement `POST /api/v1/report` for agent telemetry
- Should authenticate agents and track agent identity
- Should support pagination with `since` or cursor-based
