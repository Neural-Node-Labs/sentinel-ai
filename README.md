
# Sentinel-AI: Autonomous Server Security Active Protection (Status WORKING v1.0)

Production-ready autonomous security system with AI-powered threat detection and response.

## Features

- **Multi-LLM Support**: DeepSeek, ChatGPT, Claude, Gemini, Grok, Ollama
- **Dual-Gate Architecture**: HITL mode or autonomous AI validation
- **RAG-Based Policy**: ChromaDB-powered policy alignment checks
- **OS-Aware Tools**: Linux (iptables) and Windows (netsh) support
- **LangGraph Workflow**: State machine for log analysis → validation → execution
- **Safety Fail-Safes**: Default DENY, admin IP protection, policy enforcement
- **Privacy-First Redaction** : A local SecureFormatter intercepts all logs and telemetry, automatically scrubbing PII (API keys, SIDs, passwords) before they ever leave your network.

## Quick Start

### 1. Installation

```bash
# Clone repository
git clone https://github.com/nueva-labs/sentinel-ai.git
cd sentinel-ai

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API keys and settings
```

### 2. Initialize System

```python
python main.py
```

### 3. Run Smoke Tests

```bash
python tests/smoke_test.py
```

## Configuration

### .env Variables

- `PROVIDER`: LLM provider (deepseek|chatgpt|claude|gemini|grok|ollama)
- `API_KEY`: Provider API key
- `ADMIN_IP`: Protected administrator IP (never blocked)
- `HITL`: Human-in-the-loop mode (True|False)
- `MAX_FAILED_ATTEMPTS`: Threshold for blocking (default: 5)

### rules.md Policy

The `rules.md` file defines security policies with explicit ALLOW/DENY logic:

- IP blocking rules
- SSH authentication policies
- Firewall management rules
- Audit requirements

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ Log Listener│────▶│ Log Analysis │────▶│  Validation │
└─────────────┘     │   (AI Agent) │     │   (RAG+AI)  │
                    └──────────────┘     └──────┬──────┘
                                                 │
                                          ┌──────▼──────┐
                                          │  HITL Gate  │
                                          │ (Optional)  │
                                          └──────┬──────┘
                                                 │
                                          ┌──────▼──────┐
                                          │    Tool     │
                                          │  Execution  │
                                          └─────────────┘
```

## Safety Features

1. **Admin IP Protection**: ADMIN_IP can never be blocked
2. **Default Deny**: Ambiguous or failed validations default to DENY
3. **Policy Enforcement**: All actions must align with RAG policies
4. **Dual Validation**: AI validation + optional human approval
5. **Audit Logging**: All actions are logged with reasoning

## Docker Deployment

```bash
# Build image
docker build -t sentinel-ai .

# Run container
docker run -d \
  --name sentinel-ai \
  --env-file .env \
  -v ./chroma_db:/app/chroma_db \
  -v /var/log:/var/log:ro \
  --cap-add NET_ADMIN \
  sentinel-ai

# Or use docker-compose
docker-compose up -d
```

## Testing

The smoke test suite validates:

- Environment setup
- RAG ingestion and queries
- LLM connectivity
- Agent workflow (safe and malicious logs)
- Admin IP protection
- Policy alignment

```bash
python tests/smoke_test.py
```

## License

MIT License - see LICENSE file for details

## Support

For issues or questions, please open a GitHub issue.
