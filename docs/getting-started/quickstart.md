# Quickstart

A walkthrough of Precogly's core workflow using the sample threat model that ships with the demo data.

!!! info "Prerequisites"
Make sure Precogly is running locally. See [Installation](installation.md) if you haven't set it up yet.

## 0. Log in to Django as Super Admin

When the system first gets seeded with data, it creates a superuser with which you can access the Django admin panel. To login, go to [http://localhost:8000/admin](http://localhost:8000/admin):

- **Username:** `admin@precogly.dev`
- **Password:** `admin123`

![Django Admin Panel](../assets/images/django-admin.png)

!!! warning
Make sure to change this username and password in a production environment.

## 1. Log in

Open [http://localhost:5173](http://localhost:5173) and log in with `admin@precogly.dev` / `admin123`.

This walkthrough uses `admin@precogly.dev` throughout. The seed creates two further
accounts for exercising roles and multi-tenancy — see
[Installation](installation.md#3-log-in) — and neither is needed here.

![Login screen](../assets/images/quickstart-login.png)

## 2. Explore the home screen

After logging in, you'll land on the home screen showing the demo organization and its sample threat model.

![Home screen](../assets/images/quickstart-home.png)

## 3. Explore the Threat Libraries

Next explore the library packs.
![Threat Libraries](../assets/images/quickstart-explore-libraries.png)

Library packs are community curated groupings of:

- Components
- Threats (with links to taxonomies like CAPEC, CWE, MITRE ATT&CK, and STRIDE)
- Countermeasures (with links to standards and requirements like ASVS, PCI-DSS, DORA etc.)

You can import library packs into your organization.

## 4. Open the sample threat model

Click on the sample threat model to open it.

## 5. Review the overview screen

The overview screen gives you a summary of the threat model and a **completion checklist** that tracks your progress. Notice that **Primary assets defined** shows 0 Assets. Also, notice that **Owners assigned** shows 0 out of 110 Owners assigned. This means that countermeasures (or mitigations) to the threats have been allocated but owners to ensure that those countermeasures are implemented have not yet been identified.

![Overview screen with completion checklist](../assets/images/quickstart-overview-before.png)

## 6. Add a data asset

Precogly allows you to add data assets to components and data flows. To add a data asset to the threat model, first click on the pencil icon in the "System Context" card, then click on the "Define Assets" button.

![Add data asset via pencil icon](../assets/images/quickstart-add-data-asset.png)

Then define the kind of data assets you want to add to your data model.

![Define data asset types](../assets/images/quickstart-define-data-asset.png)

Once saved, the **Data Assets** item in the completion checklist gets checked off automatically. In case you don't see it checked, you may need to refresh your screen.

## 7. Explore the DFD editor

Navigate to the DFD editor tab (scroll down on the threat model's 'Overview' tab). The sample threat model comes with a pre-built Data Flow Diagram.

Click on different elements in the diagram (processes, data stores, external entities, and flows) to view their details. Zones and boundaries are also visible on the canvas; each has a type, and flows have a type too.

![Selected element in DFD editor](../assets/images/quickstart-dfd-editor-side-panel.png)

You can also select from the pre-built templates.

![Select DFD Template](../assets/images/quickstart-dfd-editor-select-templates.png)

## 8. View threat analysis workspace

Navigate to the threat analysis workspace screen. This is where you review the threats identified for each component and the countermeasures to address them.

The three columns map to the core threat modeling questions:

- **Column 1**: "What are we working on?" (the system, zones, components, flows, and boundaries)
- **Column 2**: "What can go wrong?" (threats, with taxonomy links like CAPEC) along with a rating and a field to enter threat actor details. Every threat has a number such as T7, and every countermeasure a number such as C3.
- **Column 3**: "What can we do about it?" (countermeasures, with compliance mappings)

Taxonomy mappings come with hyperlinks to their entries, and compliance mappings are viewable on each countermeasure.

![Threat analysis screen](../assets/images/quickstart-threat-analysis-workspace.png)

Select a countermeasure and assign it to a team member. In the demo environment the choices are `admin@precogly.dev` and `analyst@precogly.dev`, the two members of the demo organization's team; either will do. You'll see that the countermeasure color turns from red (gap) to yellow (planned). Assigning all items under a countermeasure to team members causes the threat to move from "exposed" (red) to "addressable" (yellow). Do this for a few threats.

## 9. Check your progress

Go back to the overview screen. The **Owners assigned** item in the completion checklist is now updated, reflecting the assignment you just made. You may need to refresh the page again in case you don't see the assignment to owners.

![Updated completion checklist](../assets/images/quickstart-overview-after-allocating.png)

## What's next?

- [Generate a Threat Model with AI](../guides/ai-threat-model-generation.md) — use any AI assistant (ChatGPT, Claude, Gemini, etc.) to generate a complete threat model for your own system as a CycloneDX TM-BOM file, then import it into Precogly
- [Roles and Permissions](../concepts/roles-and-permissions.md) — understand how teams, roles, and access control work
- [DFD Editor](../concepts/dfd-editor.md) — learn more about the diagram editor's features
- [Library Packs](../concepts/library-packs.md) — explore the curated threat and countermeasure packs
