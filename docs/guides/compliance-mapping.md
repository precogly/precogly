# Compliance Mapping

Map countermeasures and requirements to compliance frameworks. This guide covers both types of compliance mapping in Precogly: countermeasure-to-requirement mappings (how security controls satisfy framework requirements) and cross-framework requirement mappings (how requirements in one standard relate to requirements in another).

---

## How compliance mapping works

Precogly supports two layers of compliance mapping:

| Layer | What it connects | Defined in | Purpose |
|-------|-----------------|------------|---------|
| **Countermeasure mapping** | A security control to one or more framework requirements | `countermeasures-{framework}.yaml` | Track which controls satisfy which requirements |
| **Cross-framework mapping** | A requirement in one framework to requirements in another | `requirements-{framework}.yaml` | Show how standards overlap and relate |

Both layers are defined in library pack join files and applied automatically when the relevant frameworks are imported.

---

## Countermeasure-to-requirement mappings

These are the primary compliance mappings. When a library pack defines a countermeasure, it can also declare which compliance framework requirements that countermeasure satisfies.

### How they appear in the UI

In the **Threat Analysis** view, open a countermeasure to see its compliance coverage in the **Compliance coverage** part of its modal. Each mapping shows the framework name, requirement code, and whether coverage is full or partial.

In the **Compliance** report, frameworks appear as rows showing two metrics:

- **Covered**: the percentage of requirements that have at least one countermeasure mapped to them
- **Satisfied**: the percentage of requirements where at least one mapped countermeasure is Verified or Platform

### Compliance matrix

The **Compliance Matrix** section of the Compliance and Full reports lists, for the framework you pick, one row per requirement: the countermeasures mapped to it (with status and whether they cover it fully or partly), the threats those countermeasures mitigate, and an overdue mark. Each requirement has one of four states:

- **Satisfied**: a countermeasure fully covers it and is Verified or Platform
- **Covered**: a countermeasure fully covers it but is not in effect yet
- **Partial only**: only countermeasures that partly cover it are mapped
- **Not covered**: nothing is mapped to it

Coverage is stated against the installed pack ("N of the M requirements in this pack"). A pack often holds only part of a standard, so the matrix never claims coverage of the whole standard. **Show not covered** hides or shows the requirements with nothing mapped. Rows are grouped by family where the pack defines one, otherwise by the start of the requirement code (V1 for ASVS, SR 1 for IEC 62443). A framework that is mapped but not installed shows only its mapped requirements. Click a countermeasure number to open it in Threat Analysis. The matrix is also in the Word report and as its own CSV.

### YAML format

Countermeasure mappings live in `joins/countermeasures-{framework-slug}.yaml`:

```yaml
framework: nist-csf-2

mappings:
  - countermeasure: s3-bucket-policy
    requirements:
      - "PR.AC-4"
    sufficiency: full

  - countermeasure: lambda-least-privilege
    requirements:
      - "PR.AC-1"
      - "PR.AC-4"
    sufficiency: partial
```

| Field | Required | Description |
|-------|----------|-------------|
| `framework` | yes | Slug of the target compliance framework |
| `countermeasure` | yes | ID of a countermeasure in this pack |
| `requirements` | yes | List of `section_code` values from the framework |
| `sufficiency` | yes | `full` (fully satisfies the requirement) or `partial` (partially satisfies) |

A single countermeasure can map to requirements across multiple frameworks by having multiple overlay files. For example, a pack might include both `countermeasures-nist-csf.yaml` and `countermeasures-soc2.yaml`, so the same countermeasure appears in both frameworks' compliance reports.

### Deferred activation

If the target compliance framework has not been imported yet when the pack is imported, the mappings are stored as **pending overlays**. They activate automatically when the framework pack is imported later. No re-import is needed.

---

## Cross-framework requirement mappings

Cross-framework mappings create direct links between requirements in different compliance standards. They answer questions like "which HIPAA requirements does NIST CSF PR.AC cover?" or "which FDA Premarket requirements map to IEC 81001?".

### When to use them

Cross-framework mappings are useful when:

- **Regulatory overlap**: your organization must comply with multiple standards that address the same concerns (e.g., IEC 81001 and FDA Premarket for medical device cybersecurity)
- **Gap analysis between standards**: you want to see which requirements in a new standard are already covered by an existing standard you comply with
- **Audit preparation**: auditors want to see how your compliance posture under one framework translates to another

### How they appear in the UI

Cross-framework mappings appear in the **Cross-Framework Mappings** section of the Compliance and Full Report views. This section is located below the Compliance Mapping table.

When mappings exist, they are grouped by framework pair (e.g., "IEC 81001 &rarr; FDA Premarket") and displayed as a table with three columns:

| Column | Content |
|--------|---------|
| **Source** | The source requirement's section code and description |
| **Mapping** | A sufficiency badge — green for `full`, amber for `partial` |
| **Target** | The target requirement's section code and description |

When no cross-framework mappings exist for the frameworks in your threat model, the section shows: *"No cross-framework requirement mappings available. Mappings appear when two or more linked frameworks have requirement-level overlays defined."*

### YAML format

Requirement overlays live in `joins/requirements-{target-framework-slug}.yaml`:

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
|-------|----------|-------------|
| `framework` | yes | Slug of the **target** framework (the one being mapped to) |
| `source_framework` | yes | Slug of the **source** framework (the one being mapped from) |
| `requirement` | yes | `section_code` of a requirement in the source framework |
| `entries` | yes | List of `section_code` values in the target framework |
| `sufficiency` | yes | `full` (source requirement fully covers the target) or `partial` |

### File naming convention

The file name follows the pattern `requirements-{target-framework-slug}.yaml`, where the slug is a short identifier for the target framework (not the full framework slug with version). For example:

```
joins/
├── requirements-fda-premarket.yaml     # IEC 81001 → FDA Premarket
├── requirements-hipaa-security.yaml    # NIST CSF Health → HIPAA Security
└── requirements-iec-62443-4-1.yaml     # UL 2900 → IEC 62443-4-1
```

### Directionality

Each overlay file defines mappings in one direction: from the source framework to the target framework. If you need bidirectional mappings (A &rarr; B and B &rarr; A), create separate overlay files in each framework's pack.

For example, the IEC 81001 pack maps its requirements to FDA Premarket:

```
standards/iec-81001/joins/requirements-fda-premarket.yaml   # IEC 81001 → FDA Premarket
```

And the IMDRF Cyber pack separately maps its requirements to FDA Premarket:

```
standards/imdrf-cyber/joins/requirements-fda-premarket.yaml # IMDRF Cyber → FDA Premarket
```

### Deferred activation

Like countermeasure overlays, requirement overlays support deferred activation. If either the source or target framework is not imported when the pack is loaded, the mappings are stored as pending. They activate automatically once both frameworks are available.

This means import order does not matter. You can import the framework packs in any sequence and the requirement mappings will resolve once all dependencies are present.

### Which packs include requirement overlays

The following compliance packs ship with cross-framework requirement mappings:

| Source pack | Source framework | Target framework | File |
|------------|-----------------|-----------------|------|
| `iec-81001` | IEC 81001 | FDA Premarket | `requirements-fda-premarket.yaml` |
| `iec-81001` | IEC 81001 | ISO 14971 | `requirements-iso-14971.yaml` |
| `aami-tir57` | AAMI TIR57 | FDA Premarket | `requirements-fda-premarket.yaml` |
| `aami-tir57` | AAMI TIR57 | IEC 81001 | `requirements-iec-81001.yaml` |
| `imdrf-cyber` | IMDRF Cyber | FDA Premarket | `requirements-fda-premarket.yaml` |
| `eu-mdr-cyber` | EU MDR Cyber | IEC 81001 | `requirements-iec-81001.yaml` |
| `ul-2900` | UL 2900 | IEC 62443-4-1 | `requirements-iec-62443-4-1.yaml` |
| `pci-dss` | PCI DSS | OWASP AISVS | `requirements-owasp-aisvs.yaml` |

---

## Creating your own mappings

### Countermeasure mappings

To map your pack's countermeasures to a compliance framework:

1. Import the target compliance framework pack (or plan to — deferred activation handles ordering)
2. Create a file `joins/countermeasures-{framework-slug}.yaml` in your pack
3. Reference countermeasure IDs from your pack and `section_code` values from the framework
4. Set `sufficiency` to `full` or `partial` for each mapping

### Cross-framework requirement mappings

To create requirement-to-requirement mappings between two frameworks:

1. Determine which compliance pack should own the mapping — typically the source framework's pack
2. Create a file `joins/requirements-{target-slug}.yaml` in that pack
3. Set `framework` to the target framework's slug and `source_framework` to the source framework's slug
4. For each mapping entry, reference a `section_code` from the source framework under `requirement` and one or more `section_code` values from the target framework under `entries`

!!! tip
    A requirement can map to multiple entries in the target framework. Use this when a single source requirement covers several narrower requirements in the target standard.

### Choosing sufficiency

| Value | When to use |
|-------|-------------|
| `full` | The source requirement fully satisfies the intent of the target requirement. Implementing the source requirement means the target is met. |
| `partial` | The source requirement addresses some aspects of the target requirement, but additional controls or evidence may be needed. |

When in doubt, use `partial`. It is better to understate coverage than to overstate it — auditors will verify the mapping regardless, and `partial` signals that further review is warranted.

---

## Troubleshooting

**Cross-framework mappings not appearing in the report**
: Both the source and target framework packs must be imported, and both frameworks must be linked to the threat model (through countermeasure mappings). If either framework has no countermeasures mapped in the threat model, it won't appear in the compliance report and its cross-framework mappings won't show.

**Compliance mappings not appearing after importing a pack**
: The compliance framework pack must be imported for mappings to activate. If you imported the content pack first, import the framework pack — pending overlays will activate automatically.

**"No cross-framework requirement mappings available" message**
: This means none of the frameworks linked to your threat model have requirement-level overlays defined between them. This is expected if you're using frameworks that don't have published requirement mappings (e.g., OWASP and SOC 2 don't have standard requirement-to-requirement mappings between them). Check the [table above](#which-packs-include-requirement-overlays) to see which framework pairs have mappings.

**Mappings appear for some framework pairs but not others**
: Requirement overlays are authored per framework pair. If you have frameworks A, B, and C linked, and overlays exist for A&rarr;B but not A&rarr;C, only the A&rarr;B mappings will appear. Create a `requirements-{c-slug}.yaml` file in pack A to add A&rarr;C mappings.

---

## What's next

- [Library Packs](../concepts/library-packs.md): how packs, overlays, and dependencies work
- [Creating Library Packs](../contributing/creating-library-packs.md): author guide for pack YAML schema
- [IEC 62443 Recipe](../recipes/iec-62443.md): tiered compliance with SL-T/SL-A gap analysis
- [EU Banking Recipe](../recipes/eu-banking.md): multi-framework compliance for financial institutions
