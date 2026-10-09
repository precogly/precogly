# Guest Editor

The guest editor provides a local, account-free threat-modeling workflow at
[`/guest`](http://localhost:5173/guest). You can define context, draw a DFD, record
threats and countermeasures, and save the model as CycloneDX 2.0 TM-BOM JSON, the same
shape the signed-in workspace exports and imports.

!!! warning "Save your work"
    Guest models are not stored in Precogly's database. Use **Save** or **Save As**
    before closing the tab or navigating away.

## Start a guest model

Open `/guest` on your Precogly installation. Click the model title to rename it, then use
**Add / Edit Context** to record:

- Session facilitator, participants, and meeting date
- System description and business criticality
- Data assets, classifications, and CIA ratings
- Assumptions and their validity (unverified, verified, invalid, unknown)
- Explicit out-of-scope items

This context is included in the saved CycloneDX file and the guest Word report.

![Guest Editor system context dialog](../assets/images/guest-editor-context.png)

## Draw the data flow diagram

Use the toolbar to add processes, data stores, human and system actors, zones, and
system-scope containers. Connect nodes with flows and draw boundaries between zones. Edit
each item in the side panel: zones have a type and an optional trust level, flows have a
type and an authentication list, and boundaries have a type and crossing requirements,
with the same Advanced sections as the signed-in editor.

The notation selector switches between **DFD3** and **Yourdon** shapes. The model's
notation is retained when you save and reopen the CycloneDX file.

See [DFD Editor](../concepts/dfd-editor.md) for the shared canvas concepts and keyboard
shortcuts. Features that depend on an organization, library packs, or backend records are
available only in the signed-in workspace.

## Add threats and countermeasures

Click **Analyze Threats** to open the three-column guest analysis view:

1. Select a component, system scope, flow, zone, or boundary.
2. Add a threat with a name, description, level (info to critical), optional STRIDE
   category, and status. A threat can apply to several targets at once, or to the whole
   system; **Edit targets** changes the list.
3. Record a decision rationale when accepting, delegating, or eliminating a threat.
4. For threats marked **Mitigate**, add one or more countermeasures and select their
   control types. A countermeasure can be linked to several threats.

Threats and countermeasures carry numbers (`T3`, `C2`). They are stored in the file and
never reused, even after closing and reopening it. You can sort threats by status, level,
or name and return to the diagram at any time. Deleting a node or edge that was a
threat's only target deletes the threat; a countermeasure linked to nothing else goes with
it.

## Save and reopen files

Guest files use the `.cdx.json` extension and contain a CycloneDX 2.0 Threat Modeling
BOM. A file keeps its serial number across saves, and its version goes up when the content
changed. Files saved by earlier versions of Precogly do not open in this version; to open
one as it was, run a previous version in Docker.

The guest editor edits the first blueprint of a file. When a file has more blueprints, a
notice says so ("This file has N more blueprints. They are not shown here and are kept
when you save."), and a threat that also targets something in a hidden blueprint keeps
that target. Everything else the guest editor does not show (risks beyond the level,
business objectives, review details, attack trees) is kept and written back unchanged.
Anything in a file that could not be read as it was is listed on screen when the file
opens.

- **Save** writes to the currently opened file when the browser supports the File System
  Access API. The first save prompts for a location.
- **Save As** always prompts for a new filename.
- **Open** loads a previously saved guest CycloneDX file.
- **Cmd/Ctrl+S** performs the same action as **Save**.

Browsers without the File System Access API download a new `.cdx.json` file on save and
use a file picker when opening a model. Keep the most recent download as the current copy.

## Export and report

The diagram toolbar can export the canvas as PNG or SVG. From **Analyze Threats**, click
**Report** to download a Word document containing the system context, DFD image, threats,
and countermeasures.

The guest report and file are point-in-time exports. Update and save them again after
changing the model.

## Guest and signed-in workflows

Guest mode is useful for workshops, evaluations, and local modeling without account
setup. Use the signed-in workspace when you need organization libraries, collaboration,
ownership, compliance mappings, risk tracking, or server-side persistence. A file moves
both ways between the guest editor and the signed-in workspace with the same threats,
targets, and numbers.

For interchange details, see [Importing and Exporting](importing-exporting.md).
