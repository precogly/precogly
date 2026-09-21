# Library Packs — Author Guide

Library packs are modular bundles of threat-modeling content (components, threats, countermeasures, DFD templates, and compliance frameworks) that organizations install into Precogly. This guide covers everything you need to create a pack.

---

## Pack Types

| `pack_type` | What it contains | Example |
|---|---|---|
| `technology` | Components only | `aws`, `azure`, `gcp` |
| `full` | Components + threats + countermeasures + joins + templates | `aws` |
| `compliance` | Framework definitions with requirements | `nist-csf`, `pci-dss` |
| `taxonomy` | Classification entries (STRIDE, CWE, CAPEC, etc.) | `stride-taxonomy`, `cwe` |
| `template` | DFD templates or worksheets only | `stride-worksheets` |

---

## Directory Structure

Every pack is a directory under one of the category folders in `libraries/packs/`:

```
libraries/packs/
├── taxonomies/          # Classification systems (STRIDE, CWE, CAPEC, ATT&CK)
├── standards/           # Compliance frameworks (NIST CSF, OWASP, SOC 2, etc.)
├── threat-libraries/    # Technology-specific threats (AWS, Azure, GCP, etc.)
└── worksheets/          # Method worksheets for facilitated sessions (STRIDE)
```

Only `pack.yaml` is required; all other files are optional depending on pack type.

```
threat-libraries/aws/
├── pack.yaml                              # Pack metadata (required)
├── components.yaml                        # Component definitions
├── threats.yaml                           # Threat definitions
├── countermeasures.yaml                   # Countermeasure definitions
├── joins/
│   ├── components-threats.yaml            # Which threats apply to which components
│   ├── threats-countermeasures.yaml        # Which countermeasures mitigate which threats
│   ├── threats-stride.yaml               # Threat → STRIDE taxonomy mappings
│   ├── threats-cwe.yaml                  # Threat → CWE taxonomy mappings
│   ├── threats-capec.yaml                # Threat → CAPEC taxonomy mappings
│   ├── threats-mitre-attack.yaml         # Threat → ATT&CK taxonomy mappings
│   ├── countermeasures-nist-csf.yaml      # Compliance mapping to NIST CSF
│   ├── countermeasures-owasp.yaml         # Compliance mapping to OWASP
│   ├── countermeasures-soc2.yaml          # Compliance mapping to SOC 2
│   └── requirements-fda-premarket.yaml    # Cross-framework requirement mapping
└── dfd-templates/
    └── s3-lambda.yaml                     # DFD template
```

---

## pack.yaml

Pack metadata. This is the only required file.

```yaml
pack:
  schema_version: 1
  slug: aws
  name: AWS
  version: 1.1.0
  pack_type: full
  description: |
    AWS pack covering core infrastructure and AI/ML services
    with associated threats and countermeasures.
  author: Precogly
  depends_on:
    - taxonomies/stride-taxonomy
    - taxonomies/capec
    - taxonomies/cwe
    - taxonomies/mitre-attack
  tags:
    - aws
    - cloud
    - serverless
    - technology
    - saas
```

### Field Reference

| Field | Required | Description |
|---|---|---|
| `schema_version` | yes | Pack format version. Must be `1`. See [Pack format versioning](#pack-format-versioning). |
| `slug` | yes | Unique identifier. Lowercase alphanumeric + hyphens. |
| `name` | yes | Display name. |
| `version` | yes | Semantic version (`X.Y.Z`). |
| `pack_type` | yes | `technology`, `threat`, `countermeasure`, `compliance`, `template`, `full`, or `taxonomy` |
| `description` | yes | Multi-line description. |
| `author` | no | Author name. |
| `tags` | no | Searchable tags. |
| `depends_on` | no | List of pack dependencies (see below). |

### Dependencies

Dependencies use path-format strings relative to the `libraries/packs/` root:

```yaml
depends_on:
  - taxonomies/stride-taxonomy
  - taxonomies/cwe
```

The slug is extracted from the last path segment (e.g., `taxonomies/stride-taxonomy` resolves to slug `stride-taxonomy`). Plain slugs (without `/`) also work for backward compatibility.

### Pack format versioning

`schema_version` declares which version of the pack format a pack uses. This is separate from the pack's content `version` (which tracks changes to threats, countermeasures, etc.).

- **`schema_version: 1`** — The current and only format version.
- When the app loads a pack, it checks `schema_version` against its set of supported versions. If the version is unsupported, the pack is rejected with a validation error.
- If `schema_version` is missing, a validation warning is emitted (the pack can still be imported). This allows backwards compatibility for external packs that haven't adopted the field yet.

When we change the pack structure in the future (rename folders, add required fields, change YAML layout), we will bump the schema version. This lets the app know whether it can read a given pack.

---

## components.yaml

Defines the technology components in your pack.

```yaml
components:
  - id: s3
    name: Amazon S3
    category: datastore
    type: Object Storage
    provider: aws
    description: |
      Amazon Simple Storage Service (S3) provides scalable object storage
      for data backup, archival, and analytics.

  - id: lambda
    name: AWS Lambda
    category: process
    type: Serverless Function
    provider: aws
    description: |
      AWS Lambda lets you run code without provisioning servers.

  - id: api-gateway
    name: Amazon API Gateway
    category: process
    type: API Management
    provider: aws
    description: |
      Managed service for creating, publishing, and securing APIs.
```

### Field Reference

| Field | Required | Description |
|---|---|---|
| `id` | yes | Unique within pack. Lowercase + hyphens. |
| `name` | yes | Display name. |
| `category` | yes | `process`, `datastore`, `external_human_actor`, `external_system_actor` |
| `type` | yes | Free-text component type (e.g. "Object Storage", "NoSQL Database"). |
| `provider` | no | Provider name (e.g. `aws`, `azure`, `gcp`). |
| `description` | no | Multi-line description. |

---

## threats.yaml

Defines threats. Can be component-specific or general-purpose. STRIDE and other taxonomy mappings are defined in join files (see `threats-{taxonomy}.yaml` below).

```yaml
threats:
  - id: s3-public-exposure
    name: S3 Bucket Public Exposure
    description: |
      S3 bucket is publicly accessible, exposing sensitive data
      to unauthorized users.

  - id: lambda-injection
    name: Lambda Code Injection
    description: |
      Malicious input exploits Lambda function leading to code execution.
```

### Field Reference

| Field | Required | Description |
|---|---|---|
| `id` | yes | Unique within pack. Lowercase + hyphens. |
| `name` | yes | Display name. |
| `description` | yes | What the threat is and how it occurs. |

---

## countermeasures.yaml

Defines security controls that mitigate threats.

```yaml
countermeasures:
  - id: s3-block-public-access
    name: S3 Block Public Access
    description: |
      Enable S3 Block Public Access settings at account and bucket level.
      Prevents accidental public exposure.
    control_type: preventive
    cost: low

  - id: apigw-waf
    name: API Gateway WAF Integration
    description: |
      Enable AWS WAF to protect against common web exploits.
      Block SQL injection, XSS, and known bad actors.
    control_type: preventive
    cost: medium
    default_status: platform
```

### Field Reference

| Field | Required | Description |
|---|---|---|
| `id` | yes | Unique within pack. |
| `name` | yes | Display name. |
| `description` | yes | What the control does and how it helps. |
| `control_type` | yes | `preventive`, `detective`, `corrective`, `deterrent`, `recovery`, `compensating`, or `procedural` |
| `cost` | yes | `low`, `medium`, or `high` |
| `default_status` | no | `gap` (default) or `platform`. Platform countermeasures are treated as infrastructure-level controls managed by the security team. See [Platform Controls](../docs/concepts/platform-controls.md). |

---

## Join Files

Join files live in the `joins/` directory and define the relationships between items.

### components-threats.yaml

Maps threats to the components they apply to.

```yaml
mappings:
  - component: s3
    threats:
      - threat: s3-public-exposure
        applies_to: component
      - threat: s3-data-tampering
        applies_to: component
      - threat: dataflow-eavesdropping
        applies_to: flow
      - threat: dataflow-mitm
        applies_to: flow

  - component: api-gateway
    threats:
      - threat: apigw-injection
        applies_to: both
```

`applies_to` values:

| Value | Meaning |
|---|---|
| `component` | Threat applies to the component itself |
| `flow` | Threat applies to data flows involving the component |
| `both` | Threat applies to both |

### threats-countermeasures.yaml

Maps countermeasures to the threats they mitigate.

```yaml
mappings:
  - threat: s3-public-exposure
    countermeasures:
      - s3-block-public-access
      - s3-bucket-policy
      - s3-access-logging

  - threat: lambda-injection
    countermeasures:
      - lambda-input-validation
      - lambda-vpc
      - lambda-code-signing

  - threat: apigw-injection
    countermeasures:
      - apigw-waf
      - apigw-request-validation
      - lambda-input-validation       # shared with lambda-injection
```

#### Cross-component countermeasure sharing

A countermeasure can appear in multiple threat mappings across different components. In the example above, `lambda-input-validation` is assigned to both `lambda-injection` (on the Lambda) and `apigw-injection` (on the API Gateway). This models defense-in-depth: input validation matters at both the edge and the backend.

This pattern is what enables [zone protections](../docs/concepts/zone-protections.md). When the API Gateway (in a DMZ) has `lambda-input-validation` set to platform, and the Lambda (in an inner zone) has it as a gap, Precogly can suggest inheriting the protection. Without the shared countermeasure, no match is found.

### threats-{taxonomy}.yaml

Maps threats to taxonomy entries (STRIDE, CWE, CAPEC, ATT&CK, etc.). File naming convention: `threats-{taxonomy-slug}.yaml`.

```yaml
# joins/threats-stride.yaml
taxonomy: stride

mappings:
  - threat: s3-public-exposure
    entries: [information-disclosure]
  - threat: lambda-injection
    entries: [tampering]
```

```yaml
# joins/threats-cwe.yaml
taxonomy: cwe

mappings:
  - threat: s3-public-exposure
    entries: [CWE-862, CWE-200]
  - threat: lambda-injection
    entries: [CWE-78]
```

| Field | Required | Description |
|---|---|---|
| `taxonomy` | yes | Slug of the taxonomy (must be loaded from a taxonomy pack). |
| `threat` | yes | ID of a threat in this pack (or qualified slug for cross-pack). |
| `entries` | yes | List of `external_id` values from the taxonomy. |

### Compliance Overlay Files

Map countermeasures to compliance framework requirements. File naming convention: `countermeasures-{framework-slug}.yaml`.

```yaml
# joins/countermeasures-nist-csf.yaml
framework: nist-csf-2

mappings:
  - countermeasure: s3-bucket-policy
    requirements:
      - "PR.AC-4"
    sufficiency: full

  - countermeasure: lambda-least-privilege
    requirements:
      - "PR.AC-1"
    sufficiency: partial
```

| Field | Required | Description |
|---|---|---|
| `framework` | yes | Slug of the compliance framework (must match a compliance pack). |
| `countermeasure` | yes | ID of a countermeasure in this pack. |
| `requirements` | yes | List of `section_code` values from the framework. |
| `sufficiency` | yes | `full` (fully satisfies) or `partial` (partially satisfies). |

### Cross-Framework Requirement Overlay Files

Map requirements between two compliance frameworks. File naming convention: `requirements-{target-framework-slug}.yaml`.

These overlays create direct requirement-to-requirement links between standards (e.g., IEC 81001 requirement "5.3" maps to FDA Premarket requirement "FDA-PM-1"). They appear in the **Cross-Framework Mappings** section of the Compliance report.

```yaml
# joins/requirements-fda-premarket.yaml
framework: fda-premarket-2023
source_framework: iec-81001-2021

mappings:
  - requirement: "5.3"
    entries:
      - "FDA-PM-1"
    sufficiency: full

  - requirement: "6.1"
    entries:
      - "FDA-PM-2"
      - "FDA-PM-3"
    sufficiency: partial
```

| Field | Required | Description |
|---|---|---|
| `framework` | yes | Slug of the **target** framework (the one being mapped to). |
| `source_framework` | yes | Slug of the **source** framework (the one being mapped from). |
| `requirement` | yes | `section_code` of a requirement in the source framework. |
| `entries` | yes | List of `section_code` values in the target framework. |
| `sufficiency` | yes | `full` or `partial`. |

**Deferred activation:** If either framework is not imported when the pack is loaded, the mappings are stored as pending and activate automatically when both frameworks become available.

**Directionality:** Each file defines mappings in one direction. Create separate files for each direction if needed.

---

## taxonomy.yaml

Defines external threat classification taxonomies and their entries. Taxonomy packs provide the reference data that other packs map their threats to via join files.

```yaml
taxonomies:
  - slug: cwe
    name: CWE Software Weaknesses
    description: "Common Weakness Enumeration"
    source_url: "https://cwe.mitre.org/"
    entries:
      - external_id: CWE-79
        title: Improper Neutralization of Input During Web Page Generation (XSS)
        description: "The application does not properly neutralize user-controllable input."
        reference_url: "https://cwe.mitre.org/data/definitions/79.html"
      - external_id: CWE-89
        title: SQL Injection
        description: "The application constructs SQL commands using externally-influenced input."
        reference_url: "https://cwe.mitre.org/data/definitions/89.html"
```

### Field Reference

| Field | Required | Description |
|---|---|---|
| `slug` | yes | Unique taxonomy identifier. |
| `name` | yes | Display name. |
| `description` | no | What the taxonomy is. |
| `source_url` | no | URL to the taxonomy's official home. |
| `entries[].external_id` | yes | Unique entry ID within the taxonomy (e.g., `CWE-79`, `T1190`, `spoofing`). |
| `entries[].title` | yes | Display name for the entry. |
| `entries[].description` | no | What the entry represents. |
| `entries[].reference_url` | no | Direct link to the entry's official page. |

---

## DFD Templates

Templates are pre-built diagrams stored in the `dfd-templates/` directory. Each template produces a ready-to-use canvas when a user selects it. Templates can be traditional Data Flow Diagrams with DFD semantics (nodes, edges, trust zones) or worksheets: annotation-only canvases (typically table nodes) used to facilitate a threat modeling session rather than describe a system.

```yaml
# dfd-templates/s3-lambda.yaml
template:
  slug: aws-s3-lambda
  name: "S3 + Lambda"
  description: "Simple serverless pattern with S3 storage and Lambda processing"
  category: serverless
  diagram_type: level1

canvas_data:
  nodes:
    - id: "actor-user"
      type: "humanActor"
      position: { x: 50, y: 150 }
      data:
        label: "User"
        actorType: "user"
        description: "End user uploading files"

    - id: "sb-aws"
      type: "systemScope"
      position: { x: 180, y: 50 }
      style: { width: 500, height: 300 }
      data:
        label: "AWS Serverless"

    - id: "tb-aws"
      type: "trustZone"
      parentId: "sb-aws"
      position: { x: 30, y: 50 }
      style: { width: 440, height: 220 }
      data:
        label: "AWS Account"
        zoneType: "zoneRestricted"
        technology: "AWS"

    - id: "datastore-s3"
      type: "datastore"
      parentId: "tb-aws"
      position: { x: 50, y: 60 }
      data:
        label: "S3 Bucket"
        component_ref: "s3"
        description: "Object storage for uploaded files"
        dataSensitivity: "confidential"

    - id: "process-lambda"
      type: "process"
      parentId: "tb-aws"
      position: { x: 250, y: 60 }
      data:
        label: "Lambda"
        component_ref: "lambda"
        description: "Processes uploaded files"

  edges:
    - id: "edge-1"
      source: "actor-user"
      target: "datastore-s3"
      type: "dataFlow"
      data:
        label: "Upload File"
        protocol: "HTTPS"
        encrypted: true

    - id: "edge-2"
      source: "datastore-s3"
      target: "process-lambda"
      type: "dataFlow"
      data:
        label: "S3 Event Trigger"
        protocol: "AWS Internal"
        encrypted: true
```

### Template Metadata

| Field | Required | Description |
|---|---|---|
| `slug` | yes | Unique template identifier. |
| `name` | yes | Display name. |
| `description` | yes | What the template represents. |
| `category` | yes | See template categories below. |
| `diagram_type` | yes | `context`, `level1`, or `level2` |

### Template Categories

`webApplication`, `mobileApplication`, `microservices`, `dataPipeline`, `authentication`, `paymentProcessing`, `cloudInfrastructure`, `iot`, `apiGateway`, `worksheet`, `other`

### Node Types

| `type` | Use for | Key `data` fields |
|---|---|---|
| `process` | Applications, services, functions | `technology`, `dataSensitivity`, `component_ref` |
| `datastore` | Databases, file storage, caches | `technology`, `dataSensitivity`, `component_ref` |
| `humanActor` | Users, admins, attackers | `actorType` |
| `systemActor` | External APIs, third-party services | `systemType`, `vendor` |
| `trustZone` | Network zones, security perimeters | `zoneType`, `technology` |
| `systemScope` | Top-level system containers | `owner`, `classification` |
| `table` | Workshop worksheets, annotation grids | `headerRow`, `columnWidths`, `rows` (array of `{ height, cells }`) |

Containers (`trustZone`, `systemScope`) support nesting via `parentId` and must set `style: { width, height }`.

Table nodes are canvas annotations with no DFD semantics. They do not participate in threat analysis. Each cell in `rows[].cells` supports `text`, `fill` (`yellow`, `gray`, etc.), `rowSpan`, and `colSpan`.

### Trust Zone Types

| `zoneType` | Label |
|---|---|
| `zoneInternet` | Internet / Public Zone |
| `zoneDmz` | DMZ |
| `zoneInternal` | Internal Network |
| `zoneRestricted` | Restricted Zone |

### Edge Type

All edges use `type: "dataFlow"`.

| `data` field | Required | Description |
|---|---|---|
| `label` | no | Display label on the edge. |
| `protocol` | no | `HTTP`, `HTTPS`, `gRPC`, `WebSocket`, `TCP`, `UDP`, `MQTT`, `AMQP`, `SQL`, `Custom` |
| `encrypted` | no | `true` or `false` |
| `authenticated` | no | `true` or `false` |
| `dataClassification` | no | List of: `PII`, `Customer Data`, `Financial`, `PHI`, `Confidential`, `Internal`, `Public` |
| `description` | no | Edge description. |

### Linking Nodes to Components

Use `component_ref` in a node's `data` to link it to a component defined in `components.yaml`:

```yaml
data:
  label: "S3 Bucket"
  component_ref: "s3"     # matches id in components.yaml
```

When a user creates a DFD from this template, the node will be linked to the S3 component, automatically inheriting its associated threats and countermeasures.

---

## Compliance Packs

Compliance packs define frameworks and their requirements. Other packs reference these requirements in their compliance overlay join files.

### Identifier keys: `id` vs `slug`

Different item types use different identifier keys. Using the wrong key causes silent import failures.

| Item type | Key | Why |
|---|---|---|
| Components | `id` | Pack-local. Scoped to the pack that defines them. |
| Threats | `id` | Pack-local. Scoped to the pack that defines them. |
| Countermeasures | `id` | Pack-local. Scoped to the pack that defines them. |
| Frameworks | `slug` | Shared across packs. Multiple packs reference the same framework via overlays. |
| Taxonomies | `slug` | Shared across packs. Multiple packs reference the same taxonomy via join files. |

Validation catches this automatically on import and suggests the fix.

```yaml
# standards/nist-csf/pack.yaml
pack:
  schema_version: 1
  slug: nist-csf
  name: "NIST CSF 2.0"
  version: "1.0.0"
  pack_type: compliance
  author: "Precogly"
  description: "NIST Cybersecurity Framework 2.0"
  tags:
    - compliance
    - security
    - government

frameworks:
  - slug: nist-csf-2
    name: "NIST CSF"
    version: "2.0"
    issuer: "NIST"
    description: "NIST Cybersecurity Framework"
    requirements:
      - section_code: "PR.AC-1"
        description: "Identities and credentials are managed"
      - section_code: "PR.AC-4"
        description: "Access permissions managed with least privilege"
      - section_code: "SC-8"
        description: "Transmission confidentiality and integrity"
```

---

## Cross-Pack References

When your pack depends on another, you can reference its items using qualified slugs (`{pack-slug}/{item-id}`):

```yaml
# In your threats-countermeasures.yaml, referencing another pack's countermeasure
mappings:
  - threat: my-custom-threat
    countermeasures:
      - my-local-countermeasure        # same pack — plain id
      - aws/s3-block-public-access     # different pack — qualified slug
```

Declare the dependency in `pack.yaml`:

```yaml
depends_on:
  - threat-libraries/aws
```

---

## Validation

Pack validation runs automatically when you click **Import** in the UI. If issues are found, you will see a dialog listing each problem with a suggested fix. Errors block import and must be fixed. Warnings pause the import for review; if they are acceptable, click **Import Anyway** to continue.

You can also run validation explicitly via the API:

```
POST /api/packs/validate/
{"slug": "your-pack-slug"}
```

### What validation checks

| Check | Severity | What it catches |
|---|---|---|
| Required metadata (`slug`, `name`, `version`, `pack_type`) | Error | Missing pack identity fields |
| Missing `schema_version` | Warning | Pack format version not declared |
| Unsupported `schema_version` | Error | Pack uses a format version the app cannot read |
| Valid `pack_type` enum | Warning | Typos in pack type |
| Framework entries use `slug` not `id` | Warning | Wrong key name (causes silent skip) |
| Taxonomy entries use `slug` not `id` | Warning | Wrong key name (causes silent skip) |
| Components/threats/countermeasures have `id` | Error | Missing identifier |
| Valid `control_type` in countermeasures | Warning | Invalid enum value |
| Valid `cost` in countermeasures | Warning | Invalid enum value |
| Valid `category` in components | Warning | Invalid enum value |
| Join file references resolve | Error | Broken cross-references |
| Template `component_ref` values resolve | Error | Broken template links |

---

## Validation Checklist

Before submitting a pack, verify:

- [ ] `pack.yaml` has `schema_version: 1` as the first field in the `pack:` section
- [ ] `pack.yaml` has all required fields (`slug`, `name`, `version`, `pack_type`, `description`)
- [ ] All `id` / `slug` values are unique within their file
- [ ] All `id` values are lowercase alphanumeric with hyphens (`^[a-z0-9]+(-[a-z0-9]+)*$`)
- [ ] All `control_type` values are `preventive`, `detective`, `corrective`, `deterrent`, `recovery`, `compensating`, or `procedural`
- [ ] All `cost` values are `low`, `medium`, or `high`
- [ ] All references in join files point to ids that exist in the pack (or in declared dependencies)
- [ ] All threat refs in `threats-{taxonomy}.yaml` join files resolve to valid threat IDs
- [ ] All `framework` slugs in compliance overlays match a published compliance pack
- [ ] All `source_framework` slugs in requirement overlays match a published compliance pack
- [ ] All `section_code` values match requirements in the referenced framework
- [ ] DFD template `component_ref` values match ids in `components.yaml`
- [ ] Version follows semantic versioning (`X.Y.Z`)
