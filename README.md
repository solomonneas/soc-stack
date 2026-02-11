# Solomon's S³ Stack

A unified, AI-augmented Security Operations Center toolkit. Integrates open-source security tools with MCP (Model Context Protocol) servers for AI-driven detection, investigation, and response.

## Quick Start

Deploy Solomon's S³ Stack on Proxmox VE with one command:

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/solomonneas/soc-stack/main/scripts/setup/install.sh)"
```

> Requires Proxmox VE 7.x or 8.x. Run on the Proxmox host (not inside a VM/container).

### What Gets Deployed

| Component | Description | Default Port |
|-----------|-------------|-------------|
| Wazuh 4.x | SIEM/XDR Platform | 443, 55000 |
| TheHive 5.x | Case Management | 9000 |
| Cortex 3.x | SOAR/Analyzers | 9001 |
| MISP | Threat Intel Platform | 443 |
| Zeek | Network Monitor | N/A |
| Suricata | IDS/IPS Engine | N/A |

The installer provides an interactive menu (whiptail) to select components, deployment type (LXC or VM), resource presets, and network configuration. All components are automatically integrated post-install.

## What Is This?

A complete SOC platform combining:

- **7 MCP servers** that give AI assistants direct access to your security tools
- **Deployment automation** for spinning up the full stack
- **Remediation playbooks** with real-world case evidence
- **Dashboards** for visualization and monitoring
- **Mock data generators** for demos and training

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      AI / LLM Layer                         │
│            (Claude, GPT, Kimi, or any MCP client)           │
└──────────────┬──────────────────────────────┬───────────────┘
               │         MCP Protocol         │
┌──────────────┴──────────────────────────────┴───────────────┐
│                     MCP Server Layer                         │
│  ┌───────────┐ ┌───────────┐ ┌──────────┐ ┌─────────────┐  │
│  │ wazuh-mcp │ │thehive-mcp│ │cortex-mcp│ │  misp-mcp   │  │
│  └─────┬─────┘ └─────┬─────┘ └────┬─────┘ └──────┬──────┘  │
│  ┌─────┴─────┐ ┌─────┴──────────┐ ┌──────┴──────────────┐  │
│  │ zeek-mcp  │ │ suricata-mcp   │ │    mitre-mcp        │  │
│  └─────┬─────┘ └─────┬──────────┘ └──────┬──────────────┘  │
└────────┼─────────────┼───────────────────┼──────────────────┘
         │             │                   │
┌────────┴─────────────┴───────────────────┴──────────────────┐
│                    Security Tool Layer                        │
│                                                              │
│  DETECTION          INTELLIGENCE       ANALYSIS              │
│  ┌────────┐         ┌──────┐          ┌────────┐            │
│  │ Wazuh  │         │ MISP │          │ Cortex │            │
│  │ (SIEM) │         │(TIP) │          │(SOAR)  │            │
│  └────────┘         └──────┘          └────────┘            │
│  ┌────────┐         ┌──────────┐                            │
│  │  Zeek  │         │  MITRE   │      RESPONSE              │
│  │ (NSM)  │         │ ATT&CK   │     ┌─────────┐           │
│  └────────┘         └──────────┘     │ TheHive │           │
│  ┌──────────┐                        │  (IRP)  │           │
│  │ Suricata │                        └─────────┘           │
│  │(IDS/IPS) │                                               │
│  └──────────┘                                               │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow

```
Network Traffic
    │
    ├──> Zeek (deep protocol logging)  ──> zeek-mcp
    ├──> Suricata (IDS/IPS alerts)     ──> suricata-mcp
    │
    └──> Wazuh (SIEM correlation)      ──> wazuh-mcp
              │
              ├──> MISP (IOC enrichment)   ──> misp-mcp
              ├──> Cortex (analysis)       ──> cortex-mcp
              ├──> MITRE ATT&CK (context)  ──> mitre-mcp
              │
              └──> TheHive (case mgmt)     ──> thehive-mcp
                        │
                        └──> Playbooks (remediation)
                        └──> Cases (evidence)
```

## MCP Servers

Each server follows a consistent TypeScript pattern using the official MCP SDK.

| Server | Tool | Purpose | Tools |
|--------|------|---------|-------|
| `wazuh-mcp` | Wazuh | SIEM, vulnerability management, agent monitoring | Alert queries, vulnerability scans, agent management |
| `thehive-mcp` | TheHive | Incident response platform, case management | Case CRUD, task management, observable tracking |
| `cortex-mcp` | Cortex | Observable analysis engine, automated enrichment | Analyzer execution, job management, responder actions |
| `misp-mcp` | MISP | Threat intelligence sharing, IOC management | Event/attribute CRUD, correlation, IOC export |
| `zeek-mcp` | Zeek | Network security monitoring, protocol analysis | Log queries, DNS/HTTP/SSL analysis, host investigation |
| `suricata-mcp` | Suricata | Network IDS/IPS, signature-based detection | Alert analysis, flow queries, JA3/JA4 fingerprinting |
| `mitre-mcp` | MITRE ATT&CK | Threat framework, adversary intelligence | Technique lookup, detection coverage, attribution |

## Quick Start

### Prerequisites

- Node.js 20+
- Docker and Docker Compose (for full stack deployment)
- Python 3.11+ (for Wazuh/Cortex components)

### Deploy Full Stack (Docker)

```bash
cd docs/deployment
docker compose up -d
```

This starts: Wazuh (manager + dashboard), TheHive, Cortex, MISP, and supporting services (Elasticsearch, Cassandra, MinIO).

Zeek and Suricata run on the host/sensor, not in Docker.

### Install a Single MCP Server

```bash
cd mcp-servers/wazuh-mcp
npm install
npm run build

# Configure
export WAZUH_URL=https://your-wazuh:55000
export WAZUH_USER=admin
export WAZUH_PASSWORD=your-password

# Run
npm start
```

### Generate Mock Data

```bash
cd scripts/mock-data
./generate-all.sh    # Populates all tools with realistic demo data
```

## Project Structure

```
soc-stack/
├── README.md
├── docs/
│   ├── architecture/
│   │   ├── overview.md          # This architecture, in detail
│   │   ├── data-flow.md         # How data moves between tools
│   │   └── diagrams/            # Mermaid source files
│   ├── deployment/
│   │   ├── docker-compose.yml   # Full stack deployment
│   │   ├── proxmox/             # LXC/VM templates
│   │   └── ansible/             # Automated provisioning
│   └── integration-guide.md     # How to connect the pieces
│
├── mcp-servers/
│   ├── wazuh-mcp/
│   ├── thehive-mcp/
│   ├── cortex-mcp/
│   ├── misp-mcp/
│   ├── zeek-mcp/
│   ├── suricata-mcp/
│   └── mitre-mcp/
│
├── playbooks/                   # Incident response playbooks
│   ├── templates/
│   └── *.md
│
├── cases/                       # Case study evidence
│   ├── templates/
│   └── examples/
│
├── dashboards/                  # Frontend applications
│
├── scripts/
│   ├── setup/                   # Bootstrap scripts
│   ├── mock-data/               # Demo data generators
│   └── integration/             # Cross-tool glue
│
└── .github/
    └── workflows/               # CI/CD
```

## Real-World Evidence

This isn't theoretical. Includes sanitized case studies from production SOC work:

- **Adobe Acrobat Remediation:** 580 CVEs eliminated (82.5% reduction), all 208 Critical resolved
- **Python Vulnerability Cleanup:** 3 Critical CVEs to 0 on production endpoints
- **Wazuh Vulnerability Export:** Automated reporting pipeline for compliance

## Tech Stack

- **MCP Servers:** TypeScript, `@modelcontextprotocol/server`, Zod
- **Backend APIs:** Python (FastAPI), Node.js
- **Frontends:** React, Vite, TypeScript
- **Deployment:** Docker Compose, Ansible, Proxmox templates
- **Testing:** Vitest (TS), Pytest (Python)

## License

MIT
