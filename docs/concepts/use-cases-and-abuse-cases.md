# Use Cases and Abuse Cases

Threats start with what the system is for. A use case says what a user or system does ("Place Order"). An abuse case says how that use case can be misused ("Card testing at checkout"). The abuse case leads to threats, and the threats lead to countermeasures.

## The chain

The chain is **use case, abuse case, threat, countermeasure**.

- A use case can have many abuse cases.
- An abuse case can misuse several use cases. One abuse case ("Credential stuffing") can sit under "Log in" and "Reset password".
- An abuse case can lead to many threats, and a threat can come from several abuse cases.
- A threat keeps its countermeasures as before.

You can work in this chain with nothing but names. Every link to the diagram is optional.

| Link | What it adds |
| ---- | ------------ |
| Use case to components and flows | Suggested targets when you add a threat to one of its abuse cases, if the abuse case has none of its own |
| Abuse case to components and flows | The targets are filled in when you add a threat from the abuse case |
| Abuse case to threat actor (the spec's `abuser`) | The threat actor is filled in when you add a threat from the abuse case |
| Use case to business objectives | Context only |

Use cases and abuse cases are edited on the threat model's **Overview** tab and in the **By Use Case** view of [Threat Analysis](threat-analysis.md). They are part of the exported [TM-BOM](../guides/importing-exporting.md).

## Abuse case or threat?

The two can sound alike ("Card testing at checkout" could be read as a threat), but they do different jobs:

- An **abuse case** is how an attacker misuses a use case, step by step, in the use case's own terms. It is the security counterpart of the use case and follows its steps: the use case says "Enter payment details, submit the order"; the abuse case says "Enter card details that are not yours, submit, and repeat at a volume no real customer would". It is not rated and nothing mitigates it directly.
- A **threat** is a harmful event against specific parts of the system: customer spoofing with stolen cards on the Payment API, order flooding on the Orders DB. You rate it, triage it, and add countermeasures to it.

An abuse case leads to one or more threats, and one threat can come from several abuse cases. Two neighbours are often mixed up with these:

- A **weakness** (the kind CWE lists) is a flaw that lets an attack succeed, such as no rate limit on order creation. It is neither an abuse case nor a threat.
- A **kill chain** or **attack path** is the attacker's wider operation: getting the cards, reaching the system, cashing out. An abuse case covers only the misuse of the feature itself.

The use case and abuse case forms show this running example as placeholders in every field.

## Example: an online shop

- The use case "Place Order" is linked to the Web App, the Payment API, the Orders DB, and the flow "Web App to Payment API".
- Selecting it in the first column lists the abuse case "Card testing at checkout" in the second. Its threat actor is "Fraudster" and its target is the Payment API.
- You select the abuse case and click **Add** above the threat list (the third column). The dialog opens with the Payment API as target and "Fraudster" as actor. You pick the library threat "Payment fraud" and save.
- The threat shows under the abuse case in the **By Use Case** view, and under the Payment API in the component view. Its countermeasures (rate limit checkout, CAPTCHA after three failures) show in the countermeasures column in both views.
- A second use case, "Refund Order", has no abuse cases and no links yet. It shows two gap badges: **Not analyzed** and **Not linked to the diagram**.

## Two views, one analysis

The component view and the **By Use Case** view show the same threats. A threat is one row. When you edit it in one view, the change shows in the other.

The **By Use Case** view has four numbered columns, one per step of the chain. **1 Use cases** lists the use cases, with **Not linked to a use case** at the bottom for abuse cases that belong to none. **2 Abuse cases** lists the abuse cases of the selected use case; one linked to several use cases shows under each, marked **shared**. **3 Threats** lists the threats of the selected abuse case. **4 Countermeasures** lists the countermeasures of the selected threat.

- **+ Abuse case** on a use case adds an abuse case.
- With an abuse case selected, **Add** above the threat list opens the add threat dialog with the abuse case's threat actor and targets filled in. If the abuse case has no targets, the use case's components and flows are offered as suggestions. If neither has any, the picker starts empty. A threat with no targets is a whole-system threat.
- **Link existing**, next to it, attaches a threat the model already has. As in the component view, threat actions sit above the threat list; the tree only selects, and adds, edits or deletes use cases and abuse cases. With a use case selected, the list shows the threats of all its abuse cases; select one abuse case to add to it.

## Gap badges

| Badge | When |
| ----- | ---- |
| Not analyzed | A use case has no abuse cases |
| Not linked to the diagram | A use case has no components or flows |
| No threat | An abuse case leads to no threat |
| No countermeasure | A threat has no countermeasure (as before) |

The badges point at work that is not done yet. They do **not** change the [completion score](completion-status.md). Imported use cases have no abuse cases, so counting them would lower the score of every imported model.

## Details of a use case or abuse case

Every field except the name is optional.

- A use case has a description, main flow steps, preconditions, postconditions, success criteria, alternative flows, and exceptions. A step needs a description, and steps are numbered 1 to n. An alternative flow or exception needs a name and a condition.
- An abuse case has a description, a threat actor, preconditions, a main flow, and detection opportunities.
- An abuse case imported from a file can list the controls the file named as its mitigations. They are shown read-only and written back on export.

## Changes and approval

Use cases, abuse cases, and their links are part of the approval digest. Editing them shows **Changed since approval**.

## Related

- [Threat Analysis](threat-analysis.md)
- [Importing and Exporting](../guides/importing-exporting.md)
