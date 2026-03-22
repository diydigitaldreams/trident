# TRIDENT

![MIT License](https://img.shields.io/badge/license-MIT-green)

Red team assessment documentation platform. Single-file React application for documenting, managing, and attesting authorized security assessments.

**TRIDENT is a documentation tool. It is not an attack framework.**

---

## What It Does

- **Scope enforcement** — PerimeterGuard blocks logging of out-of-scope activity
- **Evidence chain** — SHA-256 Merkle-linked records of all assessment phases
- **HITL gates** — approval queue for sensitive tactics
- **AI advisory** — methodology guidance, MITRE mappings, finding documentation
- **CVSS calculator** — interactive v3.1 base score calculator
- **Report generation** — PTES-structured report with practitioner attestation

## 14 Views

Dashboard · Perimeter · Network Map · Workbench · Gate · Findings · Evidence · Tools · CVSS · Report · Knowledge · Integrations · Timeline · Settings

## Usage

Open `trident.jsx` as a Claude artifact. Enter your Anthropic API key in Settings to enable AI features.

**Do not use with classified, sensitive, or non-public engagement data.** Operation data is transmitted to the Claude API when using AI features.

## PerimeterGuard

Scope enforcement is powered by [PerimeterGuard](https://github.com/diydigitaldreams/perimeterguard) — kept inline for artifact compatibility. Every phase logged in the Workbench runs through three checks before writing to the evidence chain.

## Author

Jean Paul Serrano Melendez — DIY Digital Dreams.

## License

MIT © 2026 Jean Paul Serrano Melendez
