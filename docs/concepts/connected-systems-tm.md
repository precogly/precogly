# Systems and Related Threat Models

A threat model is about one system. It can also draw other systems on its diagrams and link to other threat models. Three things are involved: the **primary system**, **system assets** in the blueprints, and **related models**. All three are managed from the Overview tab.

![Relationship cards on the Overview tab showing Systems, Connected Threat Models, and Team Members](../assets/images/connected-overview-cards.png)

## Primary system

The primary system answers the question: **"What am I analyzing?"**

It is one system from your organization's inventory, chosen in the model's details. The list ends with **Create new system**, which takes a name, owner, criticality, and lifecycle state without leaving the page. A model with no primary system is fine: it still works and still exports, and the export is then named after the model.

The primary system becomes the subject of the exported document (`metadata.component`), with its criticality and lifecycle state. On import, Precogly links a system of the same name when one exists in the organization, and creates one only when the file says the exporting model had a primary system.

## System assets

A **System Scope** node on a DFD stands for a system or subsystem the diagram touches. Saving the diagram turns it into a component of kind `system` (or `subsystem` when drawn inside another scope box) in the blueprint. Components drawn inside the box belong to it.

![A System Scope node on the DFD canvas](../assets/images/connected-dfd-system-scope.png)

The scope node's panel has an optional **Linked inventory system**. Pick one to say "this box stands for that system in the inventory". Drawing or deleting a scope box never creates or deletes inventory rows; it only links to one. The model page lists the system assets of all blueprints under the primary system.

The per-component "System" select is gone. A component's system is the scope box that encloses it.

## Related models

A related model answers the question: **"What else is related?"**

1. Open a threat model and navigate to the **Overview** tab.
2. On the **Threat Models** relationship card, click **Manage**.
3. Choose a relationship type, pick a model from your organization, and click **Add**.

![Manage related threat models modal](../assets/images/connected-manage-models.png)

### Relationship types

Each link has a type, worded from this model's side:

| Type | Meaning | Rules |
| ---- | ------- | ----- |
| **depends on** | This system relies on the other | May form a loop; two systems can depend on each other |
| **is a subsystem of** | This system is part of the other | Must not form a loop |
| **is related to** | An informational cross-reference (the default) | Stored once per pair; adding it from the other side returns the existing link |
| **is superseded by** | The other model replaces this one | Must not form a loop |

A model cannot be linked to itself. The model page lists links in both directions, so a model that is the target of "is a subsystem of" shows the other model as containing it.

Related models have no effect on threats or counts. They are exported as system assets carrying a BOM-Link to the other model's serial number and version; "depends on" and "is a subsystem of" are also written as blueprint relationships. On import, a BOM-Link is resolved to a model in your organization when one carries that serial number, and the import warns when it cannot be resolved or when two models carry it.

### When to use

- A threat model covers a subsystem of a larger model
- Two models share boundaries or flows
- A newer model supersedes an older one
- A third-party provider has its own model that your system depends on

## The Systems page

**Settings > Systems** lists the organization's inventory with each system's owner, criticality, which models use it as their primary system, and how many system assets link to it. Create, edit, and delete systems here.

A system that is some model's primary system cannot be deleted on its own; the page names the models, and you give each one another primary system first. Deleting a system that is only linked from system assets unlinks those assets and deletes nothing inside the models.

The inventory view of which systems have a threat model is: systems that are some model's primary system, plus systems linked from a system asset.

## Comparison

| Aspect | Primary system | System assets | Related models |
|--------|----------------|---------------|----------------|
| Purpose | Define what the model is about | Show other systems on the diagram | Cross-reference related work |
| Links to | One inventory system | An inventory system, optionally | Other threat models |
| Effect on threats | None | Components inside the box belong to it | None |
| Direction | Not applicable | Not applicable | Directed, with a type |
| Self-reference | Not applicable | Not applicable | Prevented |
