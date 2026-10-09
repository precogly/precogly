# DFD Editor

The DFD editor is where you visually model your system: place components, draw flows, define zones, and mark boundaries.

![A completed DFD showing a food delivery app with zones, nested components, and flows](../assets/images/dfd-food-app-diagram.png)

## Toolbar

![DFD editor showing the current toolbar and an AWS serverless diagram](../assets/images/dfd-component-types.png)

| Button | What it does |
|--------|-------------|
| **Human Actor** | External human (customer, admin) |
| **System Actor** | External system (third-party API, partner service) |
| **Process** | Service, API, or function that handles data |
| **Data Store** | Database, file system, or cache |
| **Zone** | A zone with a type and, for trust and network zones, an optional trust level (DMZ, VPC, Purdue level) |
| **System Scope** | A system or subsystem box; optionally linked to a system in the inventory |
| **Draw Connection** | Draw flows between components |
| **Boundary** | Create a boundary between two zones |
| **Show flows** | Filter the canvas by flow type; see the physical view below |
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
3. Review the detected components, flows, zones, and optional clarifying questions.
4. Click **Generate DFD** and review the resulting diagram before using it for threat analysis.

If AI is not configured, **Generate** directs you to the AI provider settings page.

## Export an image

Click **Export Image** to download the current diagram as a PNG or SVG file. This exports a visual copy for reviews and documents; use the threat model export options when you need machine-readable model data.

## Components

| Type | Visual | Key properties |
|------|--------|---------------|
| **Human Actor** | Green, stick figure | Actor type (User, Admin, Engineer, ...) |
| **System Actor** | Gray, server icon | System type, Vendor |
| **Process** | Blue, gear icon | Technology, Data sensitivity, Parent process, Kind (Advanced) |
| **Data Store** | Purple, cylinder | Technology, Store type, Data sensitivity, Kind (Advanced) |
| **Zone** | Dashed border, shield | Type, Trust level (0 to 100, or not set) for trust and network zones, Zone color |
| **System Scope** | Solid border, box | System or subsystem, Linked inventory system (optional) |
| **Table** | Grid with rows and columns | Header row, column widths, cell text and fill |

Technology dropdowns are populated from your imported library packs. All components support a description field and can be linked to data assets. Drag components into a Zone, System Scope, or Process to nest them (up to 3 levels for process-to-process nesting).

**Kind** (under Advanced) is the CycloneDX asset type of the component: `service`, `api`, `gateway`, `device`, `data-store`, `queue`, `actor`, and so on. It defaults from the component's category (process, data store, actor) and from the library entry, so most users never open it. Set it by hand when the default is wrong, for example `device` for a sensor.

Changing a component's technology keeps the component, its flows, and its threats and their numbers. Library threats that no longer apply and that nobody has edited are removed; edited ones stay with a note in the threat analysis view.

## Flows and boundaries

**Flows** connect components. Click **Draw Connection**, click the source node, then click the target. Select a flow to set:

| Field | Where | Meaning |
| ----- | ----- | ------- |
| Label and description | Panel | Shown on the edge |
| Type | Panel | `data` (default), `message`, `event`, `control`, `signal`, `energy`, `physical`, `process`, or `financial`. Edges are drawn differently per type, with a small type chip for every type except `data` |
| Protocol and Encrypted | Panel | Shown for the data-like types only: `data`, `message`, `event` |
| Authentication | Panel | A list of methods (`oauth2`, `mtls`, `jwt`, and the rest of the CycloneDX list, or a custom name). Two quick choices: **Authenticated, method not specified** (Precogly's `unspecified` placeholder) and **None**. Use the real method where it is known |
| Data assets | Panel | The data assets the flow carries, with classification tags (PII, PHI, Financial, ...). Available on every flow type |
| Crosses boundary | Panel | Worked out by Precogly from the boundaries you drew; see [Zones and Boundaries](zones-and-boundaries.md) |
| Port | Advanced | Port number |

A flow's authorization list has no control in the panel; an imported value is kept and written back.

Library threats for a flow depend on its type. A library threat written for data flows is not placed on a signal, energy, or physical flow; pack authors say which flow types a threat applies to.

**Boundaries** mark a crossing between two zones. Click **Boundary**, click the first zone, then the second. The boundary line color indicates posture: red (nothing required), amber (authentication or authorization required, not both), green (both). Select a boundary to set its type, authentication and authorization lists, session settings, and, under Advanced, data validation, logging, monitoring, and a rate limit. [Zones and Boundaries](zones-and-boundaries.md) explains each field and the `none` rule.

### The physical view

**Show flows** in the toolbar filters the canvas by flow type. Untick `data` and the diagram shows only the signal, control, energy, and physical flows, which is the view an OT engineer wants. Nothing is deleted; the choice is saved with the diagram as a view setting.

## Templates

Click **Templates** to browse pre-built diagrams and worksheets from your library packs. Search by name, filter by category, and click to insert. DFD templates with library-linked components carry over their threats and countermeasures automatically. Worksheets (e.g., STRIDE per Interaction) insert annotation-only table grids for facilitating a threat modeling session.

![Template browser](../assets/images/dfd-browse-templates.png)

![An AWS Serverless template inserted into the editor](../assets/images/dfd-insert-template.png)

## Blueprints, DFDs and the primary DFD

A **blueprint** is one structural view of the system: its components, zones, boundaries, flows, data assets, assumptions, out-of-scope items, and diagrams. Every threat model has one blueprint, created with the model and named after it, and most users never see the word. Threats, countermeasures, and risks belong to the model, not to a blueprint, so a threat can target things in several blueprints.

A model with one blueprint looks as it always did. **Add blueprint** sits in the model's menu. Once a model has two or more, a **Blueprint** switcher appears in the model header and in the editor; it changes which diagrams, components, and zones are shown. **Manage blueprints** lets you rename, describe, reorder, and delete them; model types and a scope description sit under Advanced. The last blueprint cannot be deleted, and deleting one shows a preview of what goes with it, including the threats that would lose their only target.

Each blueprint can have more than one DFD. The first DFD you create in a blueprint is automatically marked **primary**: this is the diagram whose components, flows, zones, and boundaries sync to the model and drive threat analysis. Additional DFDs are **secondary** and are useful for reference diagrams, alternate views, or draft explorations; they save canvas data but do not generate analysis artifacts. There is one primary DFD per blueprint.

![DFD carousel showing a primary and secondary DFD alongside summary cards](../assets/images/dfd-multiple-dfds-carousel.png)

You can manage DFDs from the **Overview** tab of the workspace:

- **Create**: click the **+** button in the DFD carousel (or **Create First DFD** if none exist).
- **Edit**: click a DFD card to open it in the editor.
- **Delete**: open the DFD in the editor and click **Delete**. If you delete the primary DFD, the next oldest DFD in that blueprint is promoted to primary.

### When library threats appear

Saving the primary DFD adds library threats when a node or flow is first placed, when a component's technology or a flow's type changes, or when a flow is reconnected to a different end. An ordinary save adds nothing, so a library threat you deleted stays deleted. To pull in threats you removed earlier, or threats a pack upgrade added, click **Add missing library threats** in the threat analysis toolbar. See [Threat Analysis](threat-analysis.md).

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
    Our editor is a superset of Adam Shostack's [DFD3 specification](https://github.com/adamshostack/DFD3): the five canonical symbols map directly. External Entity becomes Human Actor + System Actor (we split the two), Process and Data Store are unchanged, Data Flows are arrows, and Trust Boundaries are modeled as zones (containers) with explicit boundary edges between them. We add System Scope, nested processes, zone, boundary and flow types, trust levels, security posture indicators, and compliance metadata on top of the base spec. Any DFD3 diagram can be expressed in Precogly.
