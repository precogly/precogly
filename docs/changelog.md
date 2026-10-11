# Changelog

All notable releases of Precogly are documented here.

## Unreleased

This release aligns Precogly's data model with the CycloneDX 2.0 Threat Modeling BOM (issues #583 and #584). What you draw, rate, and approve is what the export contains, and a file from any tool that writes the schema imports with warnings instead of errors.

### Breaking changes

- **Local development databases must be recreated.** The migrations assume no existing data. Run `docker compose down -v`, then `docker compose up`, and seed again.
- **Files saved or exported by earlier versions do not open.** There is no converter in the backend or the guest editor. To open such a file as it was, run the previous version of Precogly in Docker.
- **The TM-Library format is removed.** CycloneDX 2.0 TM-BOM is the one interchange format, in the signed-in workspace and the guest editor. The `import/tm-library` and `export/tm-library` endpoints are gone.
- **API paths renamed.** `/api/component-threats/` and `/api/flow-threats/` are one `/api/threats/`; `/api/trust-zones/` is `/api/zones/`; `/api/trust-boundaries/` is `/api/boundaries/`; `/api/data-flows/` and `/api/data-flow-assets/` are `/api/flows/` and `/api/flow-assets/`. The zone protection, `add_system`, `remove_system`, and `assign_system` actions are removed. Threat severity fields are replaced by `rating`; risk score columns by `inherent`, `residual`, and `target`; the risk `response` by `status` and a responses endpoint; flow and boundary authentication booleans by lists. `format_metadata` is read-only. The full table is in the [API overview](api/overview.md#changes-in-this-release).
- **MCP output fields changed.** `list_threat_models` returns `methodologies`, `lifecycle_phase`, `approved_at`, `primary_system_name`, `serial_number`, `version`, and `blueprint_count`, and `risk_scoring_method` uses the new values. Library components carry `kind`, and `search_component_library` takes a `kind` filter. Library countermeasures carry a `description`, and the countermeasure search matches it.
- **Library pack templates.** The template keys `authenticated` and the old `zoneType` family are refused; packs use `authentication` lists, spec zone types with an explicit `trustLevel`, `flowType`, `boundaryType`, and `kind`. All shipped packs are converted.
- **The shared magic-link payload** uses the unified threat shape: one list of threats with `number`, `display_number`, `whole_system`, and `targets`.

### Threats and countermeasures

- One threat table. A threat is one scenario with any number of targets: components, flows, zones, boundaries, or the whole system. It appears under each target in the analysis tree, marked shared, and counts once.
- Numbers: every threat is `T<n>` and every countermeasure `C<n>`, per model, never reused, kept through export and import, and searchable (`T7`).
- Ratings replace severities: one rating form for threats and risks with the qualitative matrix (1 to 25), OWASP Risk Rating, or a level picked directly; levels gain `info`; impact categories (including safety), estimated loss, currency, and range under Advanced. Residual risk lives on risks only.
- Countermeasure scope and provider: **Applies to** (components, flows, zones, boundaries; empty means the whole system), **Implemented by** (components and another party), **Source** (free text), and effectiveness with a "not assessed" state. Scope changes no threat's status; a control counts for a threat only when linked to it.
- Zone protections are retired. Nothing is inherited across zones any more; the "Inherited from" badge and the review dialog are gone.
- Controls that lose their last threat link are kept (unless untouched library output) and listed under **Controls not linked to any threat**, left out of gap and coverage figures.
- Library threats are generated when a node or flow is first placed, when a technology or flow type changes, or when a flow is reconnected, never on an ordinary save. Deleted library threats stay deleted; add one back from the library with **+ Add** in the Threats column. A pack upgrade changes nothing in any model and no longer breaks library links.
- Changing a component's technology keeps the component, its flows, and its threats with their numbers.
- One actor per threat: a persona, a built-in actor, or text. Personas can be created and edited in the app (**Manage personas**).
- Threat and control statuses are enforced in the services, so the Security Team gate on platform status also applies to imports.

### Diagrams, zones, boundaries, flows

- Zones have a type (thirteen CycloneDX values, `trust` by default) and an optional trust level (0 to 100, trust and network zones only; no more default of 75).
- Boundaries have a type and crossing requirements shaped like the specification: authentication and authorization lists with the `none` rule, data validation, logging, monitoring, and a rate limit policy; two boundaries between the same zones are allowed. Whether a flow crosses a boundary is computed from the boundaries drawn.
- Flows have a type (`data`, `message`, `event`, `control`, `signal`, `energy`, `physical`, `process`, `financial`); protocol and encryption apply to the data-like types; authentication is a list of methods with an "Authenticated, method not specified" quick choice. Library threats apply per flow type.
- Components have a kind (the CycloneDX asset type), defaulting from their category.
- **Show flows** filters the canvas by flow type: the physical view.
- A System Scope box is a system or subsystem asset, optionally linked to an inventory system; saving a diagram no longer creates or deletes inventory systems. The per-component System select is gone.
- Blueprints: a model has one structural view by default and can have more. The switcher appears only with two or more; each blueprint has its own primary DFD. **Manage blueprints** adds, renames, reorders, and deletes with a preview.

### Risks

- Risks have a lifecycle status (identified, assessed, mitigated, accepted, transferred, retired), a statement, domains (including safety), business objectives, and a read-only exposure derived from the linked threats. The board groups by status; bulk update sets status or owner.
- Responses replace the single response dropdown: strategy, description, status, owner, target date, and, under Advanced, cost, priority, and the countermeasures the response relies on.
- Scoring methods are `qualitative-matrix` (default) and `owasp-risk-rating`; FAIR and Mozilla RRA are listed as not yet available. The method cannot change while the model has risks.

### Context, review, approval

- Assumptions are rows with a validity (unverified, verified, invalid, unknown) and, under More, a topic, owner, impact, validation method and date, and related components. They belong to a blueprint.
- Business objectives, with criticality and owner, can be linked from threats and risks.
- Methodologies on the model (STRIDE by default; spec values or a custom name). The STRIDE summary in reports shows only when STRIDE is among them.
- The scope lock is replaced by review and approval: **Mark reviewed**, **Approve** (Security Team), **Revoke**, with a sign-off view that lists unverified assumptions and open risks. A content digest decides **Changed since approval**; undoing the change restores the approval. Lifecycle phase, validity period, and review frequency sit under Advanced, and **Review due** shows when the validity period has passed. Closes #348.
- Each model has a primary system (optional) chosen from the inventory, or created in place; the **Systems** page under Settings shows which models use each system. A system that is some model's primary system cannot be deleted on its own; deleting one that is only linked from diagrams unlinks and deletes nothing inside models.
- Related models have a type (depends on, is a subsystem of, is related to, is superseded by) with loop checks; the model page lists links in both directions.
- Every model has a serial number and a version; **Copy BOM-Link** copies `urn:cdx:<serial>/<version>`.
- Use cases that arrive with an import are listed read-only on the model page.

### Import and export

- The adapter is rewritten on the pinned CycloneDX 2.0 schema (commit `be4b1574`, 2026-09-24). Every export passes the schema and reference-integrity checks; every seeded model exports clean.
- Import never rejects a TM-BOM: schema findings and everything that cannot be stored become warnings, and the content is kept and written back on export. Import does not count as approval; the file's approval is shown as history. An imported model gets a fresh serial number; the original is kept, and BOM-Links resolve through it.
- Documents from other tools: scenarios with several targets become one threat with several targets (#533); a scenario naming several threats is split; actors that are flow ends become external actor components; per-scenario control links through `precogly:mitigates` (#529); several blueprints import in full (#538); a blueprint without a Precogly canvas gets a generated diagram (#288); the importing user's team owns the model (#337); compliance mappings resolve to installed frameworks or travel as snapshots (#342); impact descriptions round-trip (#343).
- The `precogly:` property registry is one list, generated into the guest editor and printed in [Importing and Exporting](guides/importing-exporting.md).
- Passthrough keeps attack trees, attack paths, abuse cases, other tools' properties, and unknown fields; stale references are repaired on export with a warning.

### Reports, CSV, Word, pentests, MCP

- Reports gain Review and approval, Business objectives, Countermeasure detail, and Unattached controls sections; one threat list with numbers and targets replaces the two lists by component and by flow; the Inherited countermeasures section is gone. Architecture shows zone and boundary types, trust levels, and crossing requirements.
- CSV and Word exports carry number and target columns and lose the inherited and residual severity columns; a new Assumptions CSV.
- The pentest scope groups test cases by target (component, flow, zone, boundary, system) with `T` and `C` numbers (#590).
- Dashboard counts include the `info` level.
- MCP: see the breaking changes above; the roadmap's export tool is single-format.

### Guest editor

- Reads and writes the same TM-BOM shape as the backend, generated from the same spec lists. Threats with several targets, zones and boundaries as targets, whole-system threats, controls linked to several threats, numbers stored in the file, zone, flow, and boundary types, and the `info` level.
- A file keeps its serial number across saves; the version goes up when the content changed.
- Edits the first blueprint; further blueprints are kept and written back, with a notice. Problems while opening a file are listed on screen.

### Library packs

- Pack upgrades update rows in place, so library links in models survive.
- Templates carry spec zone types with explicit trust levels, flow types, boundary types, component kinds, and authentication lists; the OT/ICS pack models Purdue levels as nested network zones with signal and control flows, device components, and a network boundary. A third sample model, "Sample LNG Process Control", is seeded.
- Threat joins can say which flow types a threat applies to (`flow_types`); an empty list means the data-like types.

### Credits

- The countermeasure `source` field, the `satisfies` import with snapshots for frameworks that are not installed, the evidence external reference, object-form requirement snapshots, the overdue filter, and the CycloneDX POA&M groundwork came from PR #559 by [JJediny](https://github.com/JJediny) and were absorbed into this branch. The ported tests keep a note of their origin.

---

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
