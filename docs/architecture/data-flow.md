# Data Flow

## Network Traffic Pipeline

```
                    Network Tap / SPAN Port
                           │
              ┌────────────┼────────────┐
              ▼                         ▼
         ┌─────────┐             ┌──────────┐
         │  Zeek   │             │ Suricata │
         │  (NSM)  │             │ (IDS/IPS)│
         └────┬────┘             └─────┬────┘
              │                        │
         conn.log                  eve.json
         dns.log                   (alerts)
         http.log                  (flows)
         ssl.log                   (protocol)
         files.log                 (fileinfo)
         notice.log                (anomaly)
              │                        │
              └───────────┬────────────┘
                          ▼
                    ┌───────────┐
                    │   Wazuh   │
                    │   (SIEM)  │
                    │           │
                    │ Correlate │
                    │ Enrich    │
                    │ Alert     │
                    └─────┬─────┘
                          │
            ┌─────────────┼─────────────┐
            ▼             ▼             ▼
      ┌──────────┐  ┌─────────┐  ┌──────────┐
      │  Cortex  │  │  MISP   │  │ TheHive  │
      │(Analyze) │  │ (Intel) │  │ (Cases)  │
      └──────────┘  └─────────┘  └──────────┘
```

## Endpoint Monitoring Pipeline

```
      Endpoint Agents (Windows, Linux, macOS)
              │
              │  Wazuh Agent
              │  (syscheck, rootcheck, syscollector, vulnerability-detector)
              │
              ▼
        ┌───────────┐
        │   Wazuh   │
        │  Manager  │
        └─────┬─────┘
              │
              ├──> Vulnerability alerts ──> TheHive (auto-create cases)
              ├──> File integrity     ──> Cortex (hash analysis)
              ├──> IOC matches        ──> MISP (correlation check)
              └──> All alerts         ──> MITRE ATT&CK (TTP mapping)
```

## Threat Intelligence Pipeline

```
      External Feeds                    Internal Sightings
      (OSINT, ISAC, commercial)         (from Wazuh/Zeek/Suricata)
              │                                │
              ▼                                ▼
        ┌─────────────────────────────────────────┐
        │                MISP                      │
        │                                         │
        │  Events ──> Attributes ──> Tags         │
        │     │           │           │            │
        │  Correlate   Sightings   Taxonomies      │
        │     │                    (TLP, ATT&CK)   │
        └─────┬───────────────────────────────────┘
              │
              ├──> Wazuh (IOC watchlists for real-time matching)
              ├──> Suricata (rule generation from IOCs)
              ├──> Cortex (feed analyzers with context)
              └──> TheHive (enrich case observables)
```

## AI Investigation Flow

When an LLM investigates an incident via MCP:

```
1. DETECT    ──> wazuh-mcp: "What alerts fired in the last hour?"
2. SCOPE     ──> zeek-mcp: "Show all activity for source IP X"
             ──> suricata-mcp: "Any IDS alerts involving this IP?"
3. ENRICH    ──> cortex-mcp: "Run analyzers on suspicious domain Y"
             ──> misp-mcp: "Is IP X in any threat intel events?"
4. CONTEXT   ──> mitre-mcp: "Map findings to ATT&CK techniques"
5. RESPOND   ──> thehive-mcp: "Create case with all findings"
6. DOCUMENT  ──> Generate report with evidence chain
```
