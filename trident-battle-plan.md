# TRIDENT — Battle Plan
### Red Team Assessment Documentation Platform
### Version: 5.0 | Author: Jean Paul Serrano Melendez
### Last updated: March 22, 2026

---

## 1. WHAT IT IS

TRIDENT is a single-file React application for documenting, managing, and attesting authorized security assessments. It is an operator workbench — not an attack tool. It runs in the browser, calls the Claude API for AI features, and persists all engagement data locally via window.storage.

**It is NOT:**
- A network scanner or attack framework
- A payload generator or exploit tool
- A replacement for actual security tooling
- Dependent on any backend server

**It IS:**
- A documentation and evidence platform for authorized assessments
- A scope enforcement layer (via PerimeterGuard) that prevents logging out-of-scope activity
- An AI-assisted methodology advisor (never offensive — documentation only)
- A self-contained single JSX file deployable as a Claude artifact

---

## 2. ARCHITECTURE

### Single-File React App
- One `.jsx` file — all views, logic, styles, and constants inline
- No build process, no dependencies beyond React (CDN)
- Deployed as a Claude artifact with persistent storage
- Claude API called from within the artifact for AI features

### State Model
All engagement state lives in React useState hooks, persisted to `window.storage` under key `"trident-v5"`:

```
op                — OperationConfig (perimeter, no_touch, constraints)
approvals[]       — pending/approved/rejected gate decisions
findings[]        — documented vulnerabilities
violations[]      — perimeter violations log
actions[]         — executed phase log
evidence[]        — Merkle-chained evidence records
tools[]           — tool registry (builtin + custom)
knowledge[]       — curated engagement knowledge
timeline[]        — activity feed (all events)
stealthVal        — 0–100 integer
mode              — GateMode string
```

### Persistence
- Auto-save: debounced 1000ms after any state change
- Auto-load: on mount, restore all state from storage
- Reset: wipe all state and clear storage key

---

## 3. THE 14 VIEWS

| ID | Nav Label | Icon | Purpose |
|---|---|---|---|
| `dashboard` | DASHBOARD | ◈ | Live metrics: MRR, findings, violations, evidence count, pending approvals |
| `scope` | PERIMETER | ◎ | Define operation: hosts, domains, CIDRs, no-touch, constraints, time window |
| `map` | NET MAP | 🗺 | SVG radial visualization of perimeter targets — color by test status |
| `workbench` | WORKBENCH | ⚡ | AI plan generator + assessment advisor chat + phase execution with PerimeterGuard |
| `gate` | GATE | ⏳ | Approval queue — pending/approved/rejected HITL decisions |
| `findings` | FINDINGS | 🔍 | Document vulnerabilities with severity, CWE, CVSS, remediation, ATT&CK mapping |
| `evidence` | EVIDENCE | 🔗 | Merkle-chained evidence records with SHA-256 integrity verification |
| `tools` | TOOLS | 🔧 | Tool registry — 12 builtin capability slots + custom tool registration |
| `cvss` | CVSS | 📊 | Interactive CVSS v3.1 base score calculator with vector string output |
| `report` | REPORT | 📄 | AI-generated assessment report with practitioner attestation block |
| `knowledge` | KNOWLEDGE | 🧠 | Curated engagement knowledge — manual + AI-populated, pin/approve/reject |
| `integrations` | INTEGRATIONS | 🔌 | Import (Nessus, Qualys, Burp, Nuclei, ZAP) / Export (JSON, Jira, SARIF) |
| `timeline` | TIMELINE | 📋 | Chronological activity feed — all events across all subsystems |
| `settings` | SETTINGS | ⚙ | Stealth slider + gate mode selector + API data warning |

---

## 4. PERIMETERGUARD INTEGRATION

TRIDENT imports PerimeterGuard as a dependency. It does NOT contain the class inline.

```javascript
import { PerimeterGuard } from "perimeterguard";
```

Every phase logged in the Workbench runs through three checks before writing to the evidence chain:

1. `guard.authorize(target)` — is the target inside the perimeter?
2. `guard.classify(tactic)` — is the tactic permitted?
3. `guard.gateCheck(tactic, mode)` — does the gate mode allow, gate, or block?

**Results:**
- `cleared: true + gate: "pass"` → log to evidence chain, add to actions
- `gate: "gate"` → add to approval queue, wait for HITL decision
- `cleared: false` OR `gate: "block"` → log violation, block evidence write

---

## 5. EVIDENCE CHAIN

Every authorized phase execution writes an evidence record. Records are Merkle-linked.

### Record Schema
```javascript
{
  id: string,           // uuid
  seq: number,          // sequential integer starting at 1
  ts: string,           // ISO timestamp
  operator: string,     // practitioner name from settings
  phase: string,        // phase name
  target: string,       // normalized target
  tactic: string,       // MITRE ATT&CK tactic ID
  tool: string,         // tool used
  output: string,       // simulated or real tool output
  perimeterCheck: AuthResult,
  hash: string,         // SHA-256 of integrityPayload
  prevHash: string,     // hash of previous record ("GENESIS" for first)
  integrityPayload: string // JSON string of all above fields except hash
}
```

### Hash Computation
- Uses Web Crypto API: `crypto.subtle.digest("SHA-256", encoded)`
- `integrityPayload` = JSON.stringify of all fields except `hash` itself
- Each record's `prevHash` = previous record's `hash`
- First record: `prevHash = "GENESIS"`

### Chain Verification
- Evidence view runs verification on mount and on demand
- Checks: `record.prevHash === previousRecord.hash` for each record
- Verification by `seq` number, not array index
- Any broken link flagged as tampered

---

## 6. GATE MODES

| Mode | Behavior | Recon | Exploitation | Impact |
|---|---|---|---|---|
| `observer` | Read-only — no execution permitted | BLOCK | BLOCK | BLOCK |
| `supervised` | Default — auto-clears recon, gates exploitation | PASS | GATE | BLOCK |
| `controlled` | All tactics require approval | GATE | GATE | BLOCK |
| `autonomous` | All tactics auto-approved | PASS | PASS | PASS |

`blocked_tactics` in constraints always block regardless of mode.
`gated_tactics` routing is handled by PerimeterGuard's `gateCheck()`.

---

## 7. STEALTH PROFILE

Continuous slider 0–100. Named presets at fixed values:

| Name | Value | Delay | Concurrent | Jitter | Tool Rotation |
|---|---|---|---|---|---|
| BLITZ | 0 | 0ms | 50 | None | Off |
| METHODICAL | 35 | 500ms | 10 | Low | Off |
| WHISPER | 70 | 2000ms | 3 | Medium | On |
| GHOST | 100 | 5000ms | 1 | High | On |

Computed parameters displayed live in Settings as slider moves. Parameters are documentation metadata only — TRIDENT does not execute tools directly.

---

## 8. MITRE ATT&CK TAXONOMY

14 tactics used throughout — in AI prompts, phase logging, finding documentation, and tactic constraints:

| ID | Name |
|---|---|
| TA0043 | Reconnaissance |
| TA0042 | Resource Development |
| TA0001 | Initial Access |
| TA0002 | Execution |
| TA0003 | Persistence |
| TA0004 | Privilege Escalation |
| TA0005 | Defense Evasion |
| TA0006 | Credential Access |
| TA0007 | Discovery |
| TA0008 | Lateral Movement |
| TA0009 | Collection |
| TA0011 | Command and Control |
| TA0010 | Exfiltration |
| TA0040 | Impact |

---

## 9. TOOL REGISTRY

12 builtin capability slots. Each tool has: name, description, technique categories, noise level (footprint), enabled flag.

| Slot | Tool | Footprint |
|---|---|---|
| port-scan | rustscan | high |
| port-scan | naabu | medium |
| web-fuzz | feroxbuster | high |
| web-fuzz | gobuster | medium |
| dns-enum | dnsx | low |
| subdomain | subfinder | low |
| vuln-scan | nuclei | medium |
| exploit | metasploit | high |
| ad-recon | bloodhound | medium |
| ad-recon | certipy | low |
| tunnel | ligolo-ng | low |
| http | httpx | low |

Custom tools: name, description, technique categories, noise level. Stored in tools state, persisted.

---

## 10. AI FEATURES (CLAUDE API)

All AI calls use `claude-sonnet-4-20250514`, max_tokens 1000, called from within the artifact via fetch to `https://api.anthropic.com/v1/messages`.

| Feature | View | System Prompt Purpose |
|---|---|---|
| Plan Generator | Workbench | Generate phased assessment plan from scope. Methodology only — no offensive content. |
| Assessment Advisor | Workbench | Documentation specialist for MITRE mappings, risk analysis, finding writeups. Never offensive. |
| Finding Documentation | Findings | Document vulnerability with CWE, CVSS, remediation, ATT&CK mapping. |
| Report Generator | Report | Write PTES-structured assessment report from findings + evidence + scope. |
| Knowledge Population | Knowledge | Extract defensive analysis, remediation patterns, documentation best practices. |

**All AI system prompts must:**
- Frame the AI as a documentation specialist, not an attack tool
- Never generate attack payloads, exploit code, or offensive techniques
- Reference MITRE ATT&CK for methodology classification only
- Include context (scope, findings, evidence) to produce relevant output

---

## 11. CVSS v3.1 CALCULATOR

Implements CVSS v3.1 base score calculation per FIRST.org specification.

8 base metrics:
- Attack Vector (Network / Adjacent / Local / Physical)
- Attack Complexity (Low / High)
- Privileges Required (None / Low / High)
- User Interaction (None / Required)
- Scope (Unchanged / Changed)
- Confidentiality Impact (None / Low / High)
- Integrity Impact (None / Low / High)
- Availability Impact (None / Low / High)

Outputs: numeric score (0.0–10.0), severity rating (None/Low/Medium/High/Critical), CVSS vector string.

---

## 12. REPORT STRUCTURE (PTES)

AI-generated report follows PTES methodology:

1. Executive Summary
2. Scope and Rules of Engagement
3. Methodology
4. Findings (sorted by severity)
5. Recommendations
6. Conclusion

**Attestation block** (always present, required before report is considered final):
- Practitioner name
- Certifications
- Scope confirmation checkbox
- Timestamp
- Signed attestation statement

---

## 13. NETWORK MAP

SVG radial visualization:
- Center node: TRIDENT hub
- Outer nodes: all perimeter hosts, domains, CIDRs
- Colors: gray (untested), green (tested/executed), red dashed (violation/no-touch)
- Updates live as actions and violations are logged
- Legend at bottom

---

## 14. FILE STRUCTURE

```
trident/
├── trident.jsx           ← entire application (single file)
├── README.md
└── LICENSE               ← MIT
```

No `package.json`, no `node_modules`, no build step.
The `.github/workflows/ci.yml` is optional — no automated tests for a single-file artifact.

---

## 15. VOCABULARY (AUTHORITATIVE)

All user-facing and code-level naming must use these terms. No synonyms.

| TRIDENT Term | Do NOT use |
|---|---|
| operation | engagement, project, scan |
| perimeter | scope, targets, hosts |
| no-touch | exclusions, out-of-scope, blacklist |
| constraints | rules, policy, config |
| cleared | allowed, ok, pass (in auth context) |
| footprint | noise, loudness |
| gate | approval, review, hold |
| phase | step, task, action (in workbench context) |
| practitioner | user, tester, analyst |

---

## 16. SECURITY REQUIREMENTS

- No credentials, tokens, or API keys stored in code or storage
- API key entered at runtime via Settings → stored in component state only (not persisted)
- All AI prompts framed as documentation — never offensive
- PerimeterGuard runs on every phase log — cannot be bypassed from UI
- Violations always logged — no silent failures
- Reset confirmation required before wiping engagement data
- Settings view must display warning about data transmission to Claude API

---

## 17. KNOWN GAPS (v5 — address in v6)

| Gap | Impact | Priority |
|---|---|---|
| PerimeterGuard still inline — not importing npm package | Medium — duplication with perimeterguard repo | High |
| No `.gitignore` — single file so minimal need | Low | Low |
| CI workflow not present — no automated tests | Low | Low |
| Network map does not render CIDR ranges visually | Low | Low |
| Import simulation uses Claude API (not real file parsing) | Medium | Medium |
| No multi-operator presence (Phase 10 from original battle plan) | Medium | Low |

---

## 18. RELEASE CHECKLIST

Before repo push:

- [ ] Single file — all logic, styles, views in `trident.jsx`
- [ ] PerimeterGuard imported from npm package (not inline)
- [ ] All 14 views render without errors
- [ ] All 5 Claude API features functional
- [ ] Evidence chain: records hash correctly, verification passes
- [ ] Persistence: save and restore all state fields including tools
- [ ] Gate modes: all 4 modes behave per Section 6
- [ ] Stealth slider: all presets compute correct parameters
- [ ] CVSS calculator: score matches FIRST.org spec for known inputs
- [ ] Report attestation block present and required
- [ ] Settings warning about API data transmission present
- [ ] No API keys hardcoded anywhere
- [ ] All vocabulary per Section 15
- [ ] README complete
- [ ] LICENSE present (MIT)
- [ ] GitHub repo created at `github.com/diydigitaldreams/trident`

---

## 19. SUCCESS CRITERIA

TRIDENT v5 is complete when:
1. Repo is live on GitHub
2. Single file loads and all 14 views render
3. PerimeterGuard is imported as a package dependency, not inline
4. Evidence chain hashes correctly and verification is clean
5. All AI features call Claude API successfully
6. All state persists and restores across sessions
7. No offensive content in any AI prompt or UI copy
