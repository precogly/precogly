# DFD Editor

The DFD editor is where you visually model your system — place components, draw data flows, define trust zones, and mark trust boundaries.

![A completed DFD showing a food delivery app with trust zones, nested components, and data flows](../assets/images/dfd-food-app-diagram.png)

## Toolbar

![DFD editor showing the current toolbar and an AWS serverless diagram](../assets/images/dfd-component-types.png)

| Button | What it does |
|--------|-------------|
| **Human Actor** | External human (customer, admin) |
| **System Actor** | External system (third-party API, partner service) |
| **Process** | Service, API, or function that handles data |
| **Data Store** | Database, file system, or cache |
| **Trust Zone** | Security zone with a trust level (DMZ, VPC) |
| **System Scope** | Visual grouping that defines analysis boundary |
| **Draw Connection** | Draw data flows between components |
| **Trust Boundary** | Create security boundaries between trust zones |
| **DFD3 / Yourdon** | Switch the notation used to render diagram nodes |
| **Templates** | Insert pre-built diagrams or worksheets from library packs |
| **Generate** | Build a DFD from an architecture image with a configured AI provider |
| **Analyze Threats** | Save and navigate to threat analysis |
| **Export Image** | Download the current diagram as PNG or SVG |

Click any component button to place it on the canvas. Its editing panel opens on the right.

## Choose a notation

Use the notation selector in the toolbar to switch between **DFD3** and **Yourdon** symbols. Changing the notation changes how nodes are displayed; it does not replace the components or flows in the diagram.

## Generate a DFD from an image

When an [AI provider](../getting-started/configuration.md#ai-threat-suggestions-bring-your-own-model) is configured, click **Generate** to turn an existing architecture diagram into an editable DFD:

1. Enter an application name and optional context.
2. Upload a JPEG, PNG, or WebP architecture image.
3. Review the detected components, data flows, trust zones, and optional clarifying questions.
4. Click **Generate DFD** and review the resulting diagram before using it for threat analysis.

If AI is not configured, **Generate** directs you to the AI provider settings page.

## Export an image

Click **Export Image** to download the current diagram as a PNG or SVG file. This exports a visual copy for reviews and documents; use the threat model export options when you need machine-readable model data.

## Components

| Type | Visual | Key properties |
|------|--------|---------------|
| **Human Actor** | Green, stick figure | Actor type (User, Admin, Engineer, ...) |
| **System Actor** | Gray, server icon | System type, Vendor |
| **Process** | Blue, gear icon | Technology, Data sensitivity, Parent process |
| **Data Store** | Purple, cylinder | Technology, Store type, Data sensitivity |
| **Trust Zone** | Dashed border, shield | Trust level (0–100 slider), Zone color |
| **System Scope** | Solid border, box | Technology, Owner |
| **Table** | Grid with rows and columns | Header row, column widths, cell text and fill |

Technology dropdowns are populated from your imported library packs. All components support a description field and can be linked to data assets. Drag components into a Trust Zone, System Scope, or Process to nest them (up to 3 levels for process-to-process nesting).

## Data flows and trust boundaries

**Data flows** connect components. Click **Draw Connection**, click the source node, then click the target. Select a flow to set its protocol, encryption/authentication flags, data classification tags (PII, PHI, Financial, ...), and trust zone crossing.

**Trust boundaries** mark the security perimeter between two trust zones. Click **Trust Boundary**, click the first zone, then the second. The boundary line color indicates posture: red (unconfigured), amber (partial), green (both auth and access control). Select a boundary to configure access control (RBAC, ACL, ...), authentication (SSO, Token, MFA, ...), and token settings.

## Templates

Click **Templates** to browse pre-built diagrams and worksheets from your library packs. Search by name, filter by category, and click to insert. DFD templates with library-linked components carry over their threats and countermeasures automatically. Worksheets (e.g., STRIDE per Interaction) insert annotation-only table grids for facilitating a threat modeling session.

![Template browser](../assets/images/dfd-browse-templates.png)

![An AWS Serverless template inserted into the editor](../assets/images/dfd-insert-template.png)

## Multiple DFDs

A threat model can have more than one DFD. The first DFD you create is automatically marked **primary** — this is the diagram whose components, data flows, and trust zones sync to the backend and drive threat analysis. Additional DFDs are **secondary** and are useful for reference diagrams, alternate views, or draft explorations; they save canvas data but do not generate analysis artifacts (components, threats, countermeasures).

![DFD carousel showing a primary and secondary DFD alongside summary cards](../assets/images/dfd-multiple-dfds-carousel.png)

You can manage DFDs from the **Overview** tab of the workspace:

- **Create** — click the **+** button in the DFD carousel (or **Create First DFD** if none exist).
- **Edit** — click a DFD card to open it in the editor.
- **Delete** — open the DFD in the editor and click **Delete**. If you delete the primary DFD, the next oldest DFD is automatically promoted to primary.

Only one DFD per threat model can be primary. When you need a secondary DFD's content to feed into threat analysis, delete the current primary (or its nodes) and recreate the components on the primary DFD.

## Keyboard shortcuts

| Shortcut | Action |
|----------|--------|
| **Cmd/Ctrl + S** | Save |
| **Cmd/Ctrl + Z** / **Shift + Z** | Undo / Redo |
| **Cmd/Ctrl + A** | Select all |
| **Escape** | Deselect / cancel connection |
| **Delete / Backspace** | Delete selected |
| **Cmd/Ctrl + C / V / D** | Copy / Paste / Duplicate |
| **Cmd/Ctrl + 0** | Fit to view |

Auto-saves every 30 seconds. Manual save with **Cmd/Ctrl + S**.

!!! info "Relationship to DFD3"
    Our editor is a superset of Adam Shostack's [DFD3 specification](https://github.com/adamshostack/DFD3) — the five canonical symbols map directly: External Entity becomes Human Actor + System Actor (we split the two), Process and Data Store are unchanged, Data Flows are arrows, and Trust Boundaries are modeled as trust zones (containers) with explicit boundary edges between them. We add System Scope, nested processes, trust levels, security posture indicators, and compliance metadata on top of the base spec. Any DFD3 diagram can be expressed in Precogly.
