# Changelog

All notable releases of Precogly are documented here.

## v0.4.0

**Release date:** September 15, 2026

The v0.4.0 release adds AI-powered DFD generation, a vendor-neutral AI/ML threat library, a redesigned threat triage workflow, and expanded AWS coverage.

### AI and library packs

- Added AI-powered DFD generation from architecture diagram images. A two-step flow uses a vision model to extract components, flows, and zones, then a text model generates canvas data with layout correction.
- Added vendor-neutral AI/ML threat library pack with 55 threats, 53 countermeasures, 12 components, and OWASP LLM/Agentic/MCP Top 10 taxonomies. Cross-pack AI references wired into the AWS pack.
- Expanded AWS library pack to 41 components with full taxonomy and compliance mappings, new DFD templates, and official AWS icons.
- Added STRIDE Worksheets pack with a STRIDE per Interaction table template for facilitating threat modeling sessions.

### Threat triage and control classification

- Replaced binary threat dismissal with a five-status triage workflow: Open, Accept, Mitigate, Delegate, Eliminate. Triaged threats require a decision rationale for audit traceability.
- Split the single `control_type` field into a multi-value `control_functions` list and a separate `control_nature` field (technical, administrative, or physical). Removed `procedural` from valid control function values.
- Migrated library packs and MCP server to the new control_functions/control_nature schema.

### CycloneDX TM-BOM interoperability

- Improved CycloneDX round-trip fidelity: triage status, control functions/nature, taxonomy categories, and assumptions now survive import and export via `precogly:*` properties.
- Improved CycloneDX import error messages with actionable detail about which entity failed.

### Security and OAuth

- Precogly now runs as an OAuth 2.1 authorization server.
- Added gitleaks support in CI and precommit.
- Fixed stored XSS via ComponentLibrary.icon_svg.

### DFD editor

- Added table node type with configurable size and text wrapping.
- Folded AI threat ranking into the Add Threat dialog and retired the standalone owl affordance.
- Added DFD notation switching (DFD3 / Yourdon-DeMarco).
- Allowed adding taxonomy entries to individual threat instances.

### Bug fixes

- Fixed guest editor import losing DFD layout by normalizing snake_case keys from backend export to camelCase.
- Fixed trust zone count inflation across multiple DFDs.
- Fixed CASCADE-delete on compliance requirement mappings.
- Fixed outdated and wrong MITRE taxonomy entries.
- Fixed image export cropping and added an export options dialog.
- Brought frontend CountermeasureStatus enums in sync with backend.

[View the full generated changelog](https://github.com/precogly/precogly/blob/main/CHANGELOG.md)
or [download v0.4.0](https://github.com/precogly/precogly/releases/tag/v0.4.0).

---

## v0.3.0

**Release date:** July 31, 2026

The v0.3.0 release expanded Precogly's interchange, AI-assisted modeling, risk,
reporting, and guest-editor workflows.

### Interchange and libraries

- Added CycloneDX 2.0 Threat Modeling BOM import and export alongside TM-Library JSON.
- Added full CAPEC, CWE, MITRE ATT&CK, and MITRE ATLAS taxonomy packs.
- Enriched exported models with Precogly metadata while retaining standard format compatibility.

### Threat modeling workflow

- Unified component and data-flow countermeasures into a shareable countermeasure model.
- Added countermeasure due dates, external ticket links, and history records.
- Added the risk register with table and Kanban views.
- Added the Pentests Scope workspace for deriving test priorities from a threat model.

### AI assistance

- Added grounded threat suggestions based on installed library packs.
- Added per-organization bring-your-own-model provider configuration.
- Added organization-level AI token usage tracking and reporting.

### DFD and guest editor

- Added DFD3 and Yourdon-DeMarco notation switching.
- Added threat visibility on the DFD canvas and improved canvas interactions.
- Expanded the guest editor with system context, threats, countermeasures, local
  CycloneDX save/open, image export, and Word report generation.

### Reports

- Added CSV exports for threats, countermeasures, risks, and compliance coverage.
- Added Word report generation for offline review.

[View the full generated changelog](https://github.com/precogly/precogly/blob/main/CHANGELOG.md)
or [download v0.3.0](https://github.com/precogly/precogly/releases/tag/v0.3.0).

---

## v0.2.0

**Release date:** May 26, 2026

35 merged PRs covering features, bug fixes, architecture improvements, and operational readiness.

### Features

- Delete functionality for components and countermeasures in Threat Analysis view ([#79](https://github.com/precogly/precogly/pull/79))
- Actor and attacker impact fields added to threat records ([#70](https://github.com/precogly/precogly/pull/70))
- Show/hide password toggle on login and signup forms ([#64](https://github.com/precogly/precogly/pull/64))
- Threat model import/export — added ThreatPersona/ThreatSource models, fixed round-trip fidelity ([#86](https://github.com/precogly/precogly/pull/86))
- Cross-framework requirement mappings for compliance overlays ([#50](https://github.com/precogly/precogly/pull/50))
- Improved threat model completion status indicators ([#84](https://github.com/precogly/precogly/pull/84))
- Threat libraries can now be imported without compliance packs ([#98](https://github.com/precogly/precogly/pull/98))
- Schema version added to pack.yaml with validation ([#95](https://github.com/precogly/precogly/pull/95))

### Bug Fixes

- Threat materialization on re-sync — generate threats for existing components/flows and recalculate risks on orphan deletion ([#63](https://github.com/precogly/precogly/pull/63))
- Compliance overlay instances not refreshed after pack update ([#60](https://github.com/precogly/precogly/pull/60))
- Library packs can be removed and re-added to threat models ([#57](https://github.com/precogly/precogly/pull/57))
- Data flow threats no longer auto-populated from unrelated library packs ([#46](https://github.com/precogly/precogly/pull/46))
- Filter threat picker by component's library ([#55](https://github.com/precogly/precogly/pull/55))
- Taxonomy pack slug mismatch fix ([#65](https://github.com/precogly/precogly/pull/65))
- String-list format in components-threats.yaml now rejected at validation time ([#74](https://github.com/precogly/precogly/pull/74))
- Pack version mismatch — sync_all_packs_from_source now correctly returns success=False ([#73](https://github.com/precogly/precogly/pull/73))
- Provider parsing, component matching, and UI fallback fix ([#48](https://github.com/precogly/precogly/pull/48))
- Form field overflow in modals ([#35](https://github.com/precogly/precogly/pull/35))
- Forgot password element positioning fix ([#36](https://github.com/precogly/precogly/pull/36))
- npm audit vulnerabilities resolved ([#62](https://github.com/precogly/precogly/pull/62))
- tsconfig baseUrl deprecation fix ([#67](https://github.com/precogly/precogly/pull/67))
- Validation improvements with messages bubbled up to frontend ([#78](https://github.com/precogly/precogly/pull/78))
- Component category enums unified, control_type values consistent across stack ([#87](https://github.com/precogly/precogly/pull/87))

### Architecture / Performance

- Pack resolution simplified — use filesystem as source of truth with O(1) path-based lookup ([#47](https://github.com/precogly/precogly/pull/47), [#54](https://github.com/precogly/precogly/pull/54))
- Pack directory structure simplified and libraries UI improved ([#89](https://github.com/precogly/precogly/pull/89))

### DevOps / Operational Readiness

- CI workflow added for PR checks — pytest (via docker compose) + tsc ([#90](https://github.com/precogly/precogly/pull/90), [#91](https://github.com/precogly/precogly/pull/91))
- Branch protection enabled on main (1 review required, status checks must pass)
- release-please workflow added for automated releases ([#93](https://github.com/precogly/precogly/pull/93))
- Version numbers reconciled across frontend, backend, and docs ([#92](https://github.com/precogly/precogly/pull/92))
- GitHub Milestones set up for roadmap visibility

### Documentation

- Added recipes section with IEC 62443 and EU banking recipes ([#44](https://github.com/precogly/precogly/pull/44))
- CONTRIBUTING.md added and updated ([#42](https://github.com/precogly/precogly/pull/42), [#49](https://github.com/precogly/precogly/pull/49))
- Docs for threat model import/export ([#68](https://github.com/precogly/precogly/pull/68))
- Docs for multiple DFD creation ([#76](https://github.com/precogly/precogly/pull/76))
- README updated with OWASP affiliation ([#71](https://github.com/precogly/precogly/pull/71))
- Discord link added to README ([#85](https://github.com/precogly/precogly/pull/85))

[View on GitHub](https://github.com/precogly/precogly/releases/tag/v0.2.0)

---

## v0.1.0 - First stable release

**Release date:** April 28, 2026

Initial public release of Precogly.

### Highlights

- Core threat modeling workflow
- DFD editor with nested components, trust zones, and trust boundaries
- Library packs (AWS, Azure, GCP)
- Threat analysis and reporting
- Import and export TM-BOM style JSON files
- Collaborative workspaces with roles and permissions
- Compliance mapping (DORA, CRA, ASVS, NIST CSF, SOC 2)
- Reference image support
- REST API with OpenAPI documentation

### Notes

- Early-stage release. APIs and data models may change.
- Recommended for evaluation and feedback, not production use.

[View on GitHub](https://github.com/precogly/precogly/releases/tag/v0.1.0)
