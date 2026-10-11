# Collaborative Review and Handoff

Threat models become useful evidence when the people who build the architecture, review
the threats, implement controls, and approve the residual risk can work from the same
source of truth. This guide describes a practical review and handoff process in Precogly.

## Decide who needs access

Precogly uses organization and team roles. The organization **Security Team** role manages
organization-wide security administration. Team roles determine access to a team's models:

| Role | Typical responsibility |
| --- | --- |
| **Lead** | Owns the team workflow and manages team membership. |
| **Member** | Builds and edits the team's threat models. |
| **Viewer** | Reviews the team's models without editing them. |
| **Security Team** | Administers security work across the organization. |

![Roles and permissions in settings](../assets/images/roles-and-permissions-settings.png)

Give people the least access they need for their part of the review. A model can be
visible to several contributors through team membership, while a viewer can review the
architecture and findings without changing the assessment.

When inviting a collaborator, select the team and role deliberately. Confirm the member
appears in the intended team before sharing a model for review.

![Threat model detail with team and access context](../assets/images/roles-and-permissions-threat-model-detail.png)

## Use a review sequence

For a normal architecture review, use three passes rather than asking every reviewer to
inspect everything at once.

### Architecture pass

The system owner and architect verify:

- The model name identifies the system, release, and environment.
- Context and scope describe the system being reviewed.
- Components represent meaningful processing, storage, and actor boundaries.
- Data flows have clear labels, direction, and protection properties.
- Zones have the right type, and trust levels are set where they mean something.
- Boundaries record what a crossing requires: authentication, authorization, and the rest.
- Sensitive data assets are placed on every relevant component and flow.

The primary DFD is the analysis source of truth. Use secondary DFDs for alternate views or
reference material, but do not assume that a secondary diagram feeds threat analysis.

### Security pass

Security reviewers inspect the generated or library-provided threats and confirm:

- Threats are applicable to every target they list: component, flow, zone, boundary, or the whole system.
- Ratings and threat-actor context reflect the actual environment.
- Triaged-out threats have a rationale that another reviewer can understand.
- Countermeasures are relevant to the specific threat and location.
- Owners, priorities, due dates, tickets, and evidence are current.
- Shared controls are reviewed at every threat they mitigate, and their scope (Applies to) is right.
- Controls not linked to any threat are either linked or deleted.

![Threat analysis overview](../assets/images/threat-analysis-overview.png)

### Decision pass

Risk owners and approvers review:

- The business impact of important threats.
- Inherent, residual, and target ratings, and the risk statement.
- The risk's status (identified, assessed, mitigated, accepted, transferred, retired) and its responses.
- The owner and target date for each response.
- Assumptions and their validity, exclusions, and any compensating controls.

Record decisions in the model while the evidence and architecture context are available.
Avoid keeping the final decision only in chat or a separate spreadsheet.

## Review changes safely

Before making a large review change, export a copy of the model as CycloneDX TM-BOM. It
serves as a backup, a version-control snapshot, and the file another tool reads. Keep the
export associated with the release or review date; its serial number and version identify
it.

When a reviewer changes a DFD, threat, or control, save the model and allow the workspace
to refresh before starting another major edit. After a review session, check the report and
the model overview so that the saved state—not only the current browser view—contains the
decision.

## Share a read-only review

From the threat model detail page, choose **Share** to open the magic-link dialog.

![Share button on the threat model page](../assets/images/magic-links-share-button.png)

Magic links provide a read-only view without requiring the recipient to create an account.
The recipient can review the overview, diagrams, threats, countermeasures, compliance
context, and other data included in the shared model.

![Magic-link dialog](../assets/images/magic-links-dialog.png)

Treat a magic-link URL like a password. Anyone who has it can view the model, so share it
only through an approved channel and revoke it when the review window closes. Do not put
secrets, credentials, or unredacted production data in a model intended for broad sharing.

![Read-only shared threat model](../assets/images/magic-links-shared-view.png)

Use authenticated team access when reviewers need to edit the model or when the model is
too sensitive for a public link.

## Use the guest editor for early collaboration

The guest editor supports a local, account-free workflow. It is useful for workshops,
initial architecture capture, and contributors who should not yet receive workspace
access.

![Guest editor context](../assets/images/guest-editor-context.png)

Guest work is local to the browser until the user saves or exports it. Before closing the
browser or replacing a guest file, save the current model. A guest model should be reviewed
and imported into the signed-in workspace before it becomes the team's authoritative record.

During handoff, compare the imported model with the original guest view:

- Confirm the DFD nodes, flows, zones, and boundaries are present.
- Confirm threats and countermeasures are attached to the intended targets and kept their numbers.
- Review imported statuses and warnings.
- Recheck owners, compliance mappings, risks, and assumptions.

Guest editing is not a replacement for authenticated collaboration. It does not provide
organization membership, team permissions, server-side persistence, or the same review
controls as a signed-in workspace.

## Prepare a penetration-testing handoff

Open **Pentests > Scope** after the security pass. The scope is derived from the current
threat model and gives testers a shared view of:

- In-scope and out-of-scope boundaries.
- Components, zones, and boundaries.
- Data assets and sensitive flows.
- Threat-based test cases and priorities.
- Existing countermeasures and known gaps.
- Related compliance requirements and business risks.

![Pentest scope](../assets/images/pentests-scope.png)

Review the scope with the tester before the engagement starts. The Precogly scope does not
replace authorization, rules of engagement, target lists, test windows, or safety limits.
Those operational constraints must be agreed separately.

## Produce the evidence package

Choose the report type based on the recipient:

| Recipient | Recommended output |
| --- | --- |
| Leadership | Executive report |
| Engineering and security | Technical report |
| GRC and auditors | Compliance report |
| Broad internal archive | Full report |

![Report type selector](../assets/images/report-type-selector.png)

Before distributing the report, verify:

- The report model and release are correct.
- Scope, assumptions, and exclusions are visible.
- The DFD reflects the reviewed architecture.
- Threats and controls are attached to the correct components and flows.
- Risk responses and residual ratings have been reviewed.
- The review and approval section shows the expected state.
- Compliance mappings reflect the current framework selection.
- The report date and reviewer context are recorded externally if required by policy.

Use CSV when a recipient needs structured threats, controls, risks, or compliance data. Use
the Word report for an offline review package. Retain the CycloneDX export alongside the
report when a future reviewer must compare the model with the delivered evidence.

![Report export menu](../assets/images/report-export-menu.png)

## Review and approve the model

The **Review** card on the model page records who reviewed and who approved the model.

1. A reviewer clicks **Mark reviewed**. The card shows the reviewer and the date.
2. A **Security Team** member clicks **Approve**. The sign-off view first lists what is still open: assumptions that are not verified, and risks still in the Identified status. It informs; it does not block. **Approve anyway** records the approval with the approver and the date.
3. **Revoke** withdraws the approval.

Under Advanced, the card takes the lifecycle phase, the validity period (**Valid from** and **Valid until**), and the **Review frequency** (monthly, quarterly, half-yearly, yearly, or an ISO 8601 duration such as `P18M`). When the validity period has passed, the card shows **Review due** next to the approval state, so you can still see whether the model was approved or has changed since.

### What "Changed since approval" means

When a model is approved, Precogly stores a digest of its content: components, flows, zones, boundaries, data assets, threats with their targets and ratings, countermeasures, risks, assumptions, objectives, and the rest of what the model owns. Whenever the current content differs from that digest, the card shows **Changed since approval**. Moving nodes on the diagram, comments, and reordering lists are not content and do not count. A change that is later undone makes the approval valid again, because the content is the same as what was approved.

Nothing records who made the change or when; the card only says that the content differs. The report carries the same state.

There is no scope lock any more. Approval is the record; editing stays possible, and the badge tells you the approval no longer matches.

An approval that came with an imported file is shown as history ("approved in the source document"). The imported model starts unapproved.

## Close the review

At the end of the review, make one final pass through the model and record:

- The review date and release or environment assessed.
- Reviewers and approvers, through the Review card.
- Open gaps and their owners.
- Accepted or waived exposures and their rationale, and each risk's status.
- The next reassessment trigger, such as a release, major architecture change, or control
  expiry, as the validity period and review frequency.

Then retain the final report and structured export according to the organization's evidence
retention policy. The model should make the current security decision understandable to a
new reviewer without requiring access to the original workshop or chat history.

## Related guides

- [Roles and Permissions](../concepts/roles-and-permissions.md)
- [Magic Links](../concepts/magic-links.md)
- [Guest Editor](guest-editor.md)
- [Pentest Scope](pentests.md)
- [Report Generation](report-generation.md)
- [Importing and Exporting](importing-exporting.md)
