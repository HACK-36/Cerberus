# Project Cerberus 🛡️

**An Integrated Active-Defense Security Fabric**

Cerberus is a production-grade security platform that combines WAF, deception technology, and AI-driven threat analysis to automatically detect, profile, and neutralize attacks.

## ⚠️ Legal & Ethical Notice

**IMPORTANT:** This system is designed for defensive security research and must only be deployed on infrastructure you own and control. Unauthorized deployment against third-party systems may violate laws including the Computer Fraud and Abuse Act (CFAA) and similar statutes worldwide.

### Legal Requirements
- ✅ Deploy only on systems you own or have explicit authorization to test
- ✅ Ensure compliance with local laws and regulations
- ✅ Obtain proper consent for monitoring and data collection
- ✅ Maintain data retention policies and privacy controls
- ❌ Do not deploy against third-party systems without permission
- ❌ Do not use captured data for unauthorized purposes

### Data Handling
- Only synthetic/decoy data is exposed to attackers
- No real production data enters the Labyrinth
- Captured data is retained per your retention policy (default: 90 days)
- All storage is encrypted at rest
- Audit logs are immutable and cryptographically signed

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Internet Traffic                        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │   GATEKEEPER    │  ◄── WAF + ML Triage
                    │   (WAFinity)    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │     SWITCH      │  ◄── Transparent Redirect
                    │  (Session Pin)  │
                    └───┬─────────┬───┘
                        │         │
            Normal      │         │    POI (Person of Interest)
                        │         │
              ┌─────────▼─┐   ┌──▼──────────┐
              │ Production│   │  LABYRINTH  │  ◄── Honeypot
              │   Backend │   │  (Chimera)  │
              └───────────┘   └──────┬──────┘
                                     │
                              ┌──────▼──────┐
                              │ THREAT TWIN │  ◄── AI Analysis
                              │  (Sentinel) │
                              └──────┬──────┘
                                     │
                              ┌──────▼──────┐
                              │  New Rules  │
                              │  Auto-Push  │
                              └─────────────┘
```

## 🎯 Components

### 1. **Gatekeeper (WAFinity)**
- Edge WAF with signature-based detection (ModSecurity)
- ML-based anomaly detection for zero-day threats
- Real-time traffic classification and POI tagging
- Location: `gatekeeper/`

### 2. **Switch (Transparent Router)**
- Reverse proxy with dynamic session pinning
- Seamlessly redirects suspicious sessions to Labyrinth
- Maintains attacker's view of original infrastructure
- Location: `switch/`

### 3. **Labyrinth (Chimera)**
- High-interaction honeypot with realistic decoy application
- Synthetic data generation (fake users, APIs, databases)
- Full request/response capture and payload extraction
- Network-isolated container environment
- Location: `labyrinth/`

### 4. **Threat Twin (Sentinel)**
- **Behavioral Profiler:** TTP analysis and attacker intent classification
- **Simulator:** Sandbox payload execution against shadow production code
- **Rule Generator:** Automatic WAF rule synthesis from evidence
- **Policy Orchestrator:** Auto-apply vs manual review decisions
- Location: `sentinel/`

## 🚀 Quick Start

### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+
- Python 3.11+
- Node.js 18+ (for dashboard)
- 8GB RAM minimum (16GB recommended)

### Local Development Setup

```bash
# Clone and enter directory
cd /path/to/Cerberus

# Start all services
docker-compose up -d

# Verify services are running
docker-compose ps

# View logs
docker-compose logs -f

# Access dashboard
open http://localhost:3000

# Run demo attack simulation
./scripts/demo.sh
```

### Production Deployment (Kubernetes)

```bash
# Build images
make build-all

# Deploy to cluster
kubectl create namespace cerberus
helm install cerberus ./helm/cerberus -n cerberus

# Verify deployment
kubectl get pods -n cerberus
```

## 🔄 End-to-End Flow

1. **Detection:** Request arrives → Gatekeeper analyzes (signatures + ML)
2. **Tagging:** Suspicious request flagged as POI → Event emitted
3. **Routing:** Switch pins session → Subsequent requests → Labyrinth
4. **Capture:** Labyrinth engages attacker → Records all activity + payloads
5. **Analysis:** Sentinel profiles behavior → Simulates payloads in sandbox
6. **Response:** Rule generated → Auto-pushed to Gatekeeper → Attack blocked

## 📊 API Endpoints

### Gatekeeper
- `POST /api/v1/gatekeeper/rules` - Push new WAF rule
- `GET /api/v1/gatekeeper/rules` - List active rules
- `DELETE /api/v1/gatekeeper/rules/{id}` - Remove rule

### Switch
- `POST /api/v1/switch/pin` - Pin session to Labyrinth
- `GET /api/v1/switch/sessions` - List pinned sessions
- `DELETE /api/v1/switch/pin/{session_id}` - Unpin session

### Labyrinth
- `POST /api/v1/labyrinth/decoy-config` - Update decoy templates
- `GET /api/v1/labyrinth/captures` - List captured sessions

### Sentinel
- `POST /api/v1/sentinel/simulate` - Run simulation job
- `GET /api/v1/sentinel/sim-result/{job_id}` - Get simulation result
- `POST /api/v1/sentinel/rule-propose` - Propose new rule
- `POST /api/v1/sentinel/rule-apply` - Apply rule to Gatekeeper

## 🧪 Testing

```bash
# Run all tests
make test

# Unit tests only
make test-unit

# Integration tests
make test-integration

# E2E acceptance test
make test-e2e

# Load tests
make test-load
```

## 📈 Metrics & Observability

Cerberus collects the following operational metrics:

- `time_to_detect` - Milliseconds from request to POI tag
- `time_to_redirect` - Tag to switch pin latency
- `time_to_simulate` - Sandbox execution time
- `rule_generation_confidence` - Confidence score (0-1)
- `false_positive_rate` - WAF ML false positive percentage
- `mean_time_to_block` - Average time to block repeated attacks
- `attacks_honeypotted` - Count of sessions captured
- `rules_generated` - Count of auto-generated rules

Access Grafana dashboard: `http://localhost:3001`

## 🔒 Security Architecture

### Fail-Safe Guarantees
- ✅ No production data exposed to Labyrinth (only synthetic decoys)
- ✅ Sandboxes are network-isolated (no egress except monitored proxy)
- ✅ Payloads never execute on production infrastructure
- ✅ All evidence storage encrypted at rest (AES-256)
- ✅ Immutable audit logs with cryptographic signing
- ✅ mTLS + RBAC on all admin APIs
- ✅ Panic button to immediately revert routing

### Isolation Layers
1. Network: Labyrinth in separate VLAN/namespace
2. Compute: Sandboxes in ephemeral containers with resource limits
3. Data: Zero access to production databases or secrets
4. Filesystem: Read-only mounts, ephemeral writable volumes

## 📁 Project Structure

```
cerberus/
├── gatekeeper/           # WAF + ML triage
│   ├── nginx/            # NGINX configs
│   ├── modsecurity/      # ModSecurity rulesets
│   ├── ml/               # Anomaly detection models
│   └── api/              # Rule management API
├── switch/               # Session routing proxy
│   ├── envoy/            # Envoy proxy configs
│   └── api/              # Session management API
├── labyrinth/            # Honeypot application
│   ├── app/              # Decoy web application
│   ├── decoy-gen/        # Synthetic data generator
│   └── capture/          # Request capture service
├── sentinel/             # AI analysis engine
│   ├── profiler/         # Behavioral analysis
│   ├── simulator/        # Payload sandbox
│   ├── rule-gen/         # Rule synthesis
│   └── orchestrator/     # Policy decisions
├── shared/               # Shared libraries
│   ├── events/           # Event schemas
│   ├── models/           # Data models
│   └── utils/            # Common utilities
├── infrastructure/       # Deployment configs
│   ├── docker/           # Dockerfiles
│   ├── kubernetes/       # K8s manifests
│   ├── helm/             # Helm charts
│   └── terraform/        # Infrastructure as code
├── tests/                # Test suite
│   ├── unit/
│   ├── integration/
│   ├── e2e/
│   └── load/
├── scripts/              # Automation scripts
│   ├── demo.sh           # Demo attack scenario
│   ├── setup.sh          # Initial setup
│   └── panic.sh          # Emergency shutdown
├── docs/                 # Documentation
│   ├── architecture.md
│   ├── api-reference.md
│   ├── deployment.md
│   └── security.md
└── dashboard/            # Web UI (React)
```

## 🎬 Demo Scenario

Run the included demo to see Cerberus in action:

```bash
./scripts/demo.sh
```

The demo simulates:
1. Normal traffic (passes through to production)
2. SQLi attack attempt (tagged as POI)
3. Session redirect to Labyrinth
4. Payload capture and analysis
5. Simulation in sandbox
6. Auto-generation and push of WAF rule
7. Subsequent identical attack blocked

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## 📄 License

[Apache 2.0](LICENSE) - See LICENSE file for details

## 🆘 Support & Troubleshooting

### Common Issues

**Gatekeeper not starting**
```bash
# Check ModSecurity logs
docker-compose logs gatekeeper
# Verify rule syntax
make validate-rules
```

**Labyrinth sessions not captured**
```bash
# Verify Switch routing
curl http://localhost:8080/api/v1/switch/sessions
# Check network connectivity
docker-compose exec switch ping labyrinth
```

**Sentinel simulations timing out**
```bash
# Increase sandbox timeout
export SENTINEL_SANDBOX_TIMEOUT=300
# Check resource limits
docker stats
```

### Panic Button

Emergency shutdown of all routing and sandboxes:
```bash
./scripts/panic.sh
```

This will:
- Stop all session pinning immediately
- Destroy all active sandboxes
- Revert Gatekeeper to safe default rules
- Preserve audit logs and evidence

## 📞 Contact

For security issues, email: security@your-domain.com

---

**Built with 🛡️ for defensive security research**

*Remember: With great power comes great responsibility. Use ethically and legally.*
