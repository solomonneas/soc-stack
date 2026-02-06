# MCP Servers

Seven Model Context Protocol servers for AI-augmented security operations.

## Servers

### API-Based (REST client)
| Server | Tool | Port | Auth |
|--------|------|------|------|
| `wazuh-mcp` | Wazuh Manager | 55000 | User/Password |
| `thehive-mcp` | TheHive | 9000 | API Key (Bearer) |
| `cortex-mcp` | Cortex | 9001 | API Key (Bearer) |
| `misp-mcp` | MISP | 443 | API Key (Header) |

### Log-Based (File parser)
| Server | Tool | Input | Format |
|--------|------|-------|--------|
| `zeek-mcp` | Zeek | Log directory | JSON or TSV |
| `suricata-mcp` | Suricata | EVE JSON | Newline-delimited JSON |

### Data-Based (Offline knowledge base)
| Server | Tool | Source | Format |
|--------|------|--------|--------|
| `mitre-mcp` | MITRE ATT&CK | STIX bundles | JSON (auto-downloaded) |

## Shared Configuration

All servers share:
- `tsconfig.base.json` for TypeScript compiler settings
- Consistent project structure (see architecture docs)
- Zod-validated environment variable config
- stdio transport by default

## Quick Install (any server)

```bash
cd <server-name>
npm install
npm run build
# Set required env vars (see each server's README)
npm start
```

## Development

```bash
cd <server-name>
npm install
npm run dev     # Watch mode with tsx
npm test        # Run vitest
```
