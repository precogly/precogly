# Report Generation

Precogly generates threat model reports that serve as evidence artifacts for stakeholders, auditors, and compliance teams. Reports are rendered client-side from data returned by the `/api/threat-models/{id}/report/` endpoint, so they always reflect the current state of your threat model.

## Accessing the report view

Open a threat model from the dashboard, then select the **Report** tab in the workspace sidebar. The report view loads automatically and defaults to the Executive report type.

![The Report tab in the threat model workspace sidebar](../assets/images/report-workspace-tab.png)

## Choosing a report type

Four report types are available. Click the corresponding card at the top of the report view to switch between them.

![Report type selector cards showing Executive, Technical, Compliance, and Full Report options](../assets/images/report-type-selector.png)

### Executive

High-level overview for leadership. Surfaces the review and approval state, the STRIDE summary, countermeasure status, top gaps, risk register, and critical findings without exposing low-level threat or component details. Scope, business objectives, and compliance coverage appear in summary form; assumptions are limited to flagged items only.

### Technical

Detailed analysis for engineers. Includes full architecture (zone and boundary types, crossing requirements), data assets, components and flows, individual threat detail with numbers and targets (including triaged threats), countermeasure detail (status, gaps, waived, and controls not linked to any threat), and a complete findings and action items list. The risk register is shown in summary form.

### Compliance

Audit-ready view organized around framework coverage. Contains the full compliance mapping and cross-framework mappings, triaged threats, all countermeasure categories, the risk register, assumptions review, compliance-specific findings, and a completion status checklist. Data assets and the STRIDE summary appear in summary form.

### Full Report

Every section at full depth. Includes all sections listed in the reference table below with no filtering or summarization.

## Report sections reference

The table below shows which sections appear in each report type. **Full** means the section is shown at full detail; **Summary** means a condensed version; other labels indicate specific filtering (e.g., only flagged assumptions or only critical findings).

| Section                  | Executive | Technical | Compliance | Full |
|--------------------------|-----------|-----------|------------|------|
| Executive Summary        | Full      | --        | --         | Full |
| Review and Approval      | Summary   | Summary   | Full       | Full |
| Scope and Assumptions    | Summary   | Summary   | Full       | Full |
| Business Objectives      | Summary   | Summary   | Full       | Full |
| Architecture             | --        | Full      | --         | Full |
| Data Assets              | --        | Full      | Summary    | Full |
| Components and Flows     | --        | Full      | --         | Full |
| STRIDE Summary           | Full      | Full      | Summary    | Full |
| Threat Detail            | --        | Full      | --         | Full |
| Triaged Threats          | --        | Full      | Full       | Full |
| Countermeasure Status    | Full      | Full      | Full       | Full |
| Countermeasure Detail    | --        | Full      | --         | Full |
| Gaps                     | Top 3     | Full      | Full       | Full |
| Waived Countermeasures   | Count     | Full      | Full       | Full |
| Unattached Controls      | --        | Full      | Full       | Full |
| Risk Register            | Full      | Summary   | Full       | Full |
| Compliance Mapping       | Summary   | --        | Full       | Full |
| Cross-Framework Mappings | --        | --        | Full       | Full |
| Assumptions Review       | Flagged   | --        | Full       | Full |
| Findings                 | Critical  | Full      | Compliance | Full |
| Completion Status        | --        | --        | Full       | Full |

## Exporting reports

The **Export CSV** dropdown in the top-right corner of the report view provides the CSV exports and the Word report.

![Export dropdown showing Threats, Countermeasures, Risks, Compliance Coverage, and Full Report (Word) options](../assets/images/report-export-menu.png)

### CSV exports

Separate CSV files are available, each covering one domain of the threat model:

- **Threats**: number, name, description, targets (or "Whole system"), classifications, level, score, rating method, status, business objectives, and the linked control numbers
- **Countermeasures**: number, name, control type, status, priority, applies to, implemented by, source, compliance standards, owner, and one row per linked threat with its number and targets
- **Risks**: risk register entries with status, statement, the inherent, residual, and target ratings, and responses
- **Compliance Coverage**: framework control mappings and coverage status
- **Assumptions**: description, validity, topic, owner, and validation details

The STRIDE summary appears only when STRIDE is among the model's methodologies. Controls not linked to any threat are listed on their own and left out of the gap and coverage figures.

Click the desired item in the dropdown to download the corresponding CSV file immediately.

### Word export

Select **Full Report (Word)** from the same dropdown to generate a `.docx` document containing the complete report. The Word export packages all sections into a single file suitable for offline review or distribution to stakeholders who do not have Precogly access.

## Tips

| Audience              | Recommended report type |
|-----------------------|-------------------------|
| C-suite / board       | Executive               |
| Security engineers    | Technical               |
| Auditors / GRC teams  | Compliance              |
| Internal archive      | Full                    |

- Switch between report types freely. The underlying data is the same; only the sections and their depth change.
- Use CSV exports when you need to import threat or compliance data into spreadsheets or external tools.
- Use the Word export to share a self-contained report with reviewers outside the platform.
