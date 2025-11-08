# Cerberus Architecture

## System Overview

Cerberus is a distributed security fabric with four primary subsystems that detect, analyze, and neutralize threats in real-time.

## High-Level Flow

```
Request → Gatekeeper (WAF+ML) → Switch (Router) → Production/Labyrinth
                                                           ↓
                                                    Threat Twin (AI)
                                                           ↓
                                                    Auto-Block Rules
```

## Components

### 1. Gatekeeper (WAFinity)
- **Purpose:** Edge WAF with ML anomaly detection
- **Tech:** NGINX + ModSecurity + Python ML
- **Performance:** 10K req/s, <50ms p99
- **Output:** ALLOW | BLOCK | TAG_POI

### 2. Switch (Session Router)
- **Purpose:** Transparent session redirect
- **Tech:** Envoy + Lua + Redis
- **Function:** Pin POI sessions to Labyrinth
- **Transparency:** Preserves Host header & URLs

### 3. Labyrinth (Chimera)
- **Purpose:** High-interaction honeypot
- **Tech:** FastAPI + PostgreSQL + Faker
- **Content:** Synthetic users, APIs, admin panels
- **Capture:** Full requests + payload extraction

### 4. Threat Twin (Sentinel)
- **Profiler:** TTP mapping, intent classification
- **Simulator:** Sandbox payload execution
- **Rule Generator:** Auto-create WAF signatures
- **Orchestrator:** Auto-apply vs manual review

## Data Models

See `shared/events/schemas.py` for complete event definitions.

## Security Boundaries

- Labyrinth: Isolated network, no production data
- Sandboxes: Ephemeral, no egress, resource limited
- Evidence: Encrypted at rest, immutable logs
- APIs: mTLS + RBAC required
