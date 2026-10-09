# Completion Status

The completion status checklist tracks how complete a threat model is across 7 key areas. It appears on the Overview tab of every threat model and updates automatically as you build out your model.

![Completion status checklist on the Overview tab](../assets/images/completion-status-overview.png)

## Checklist items

All 7 items are auto-computed from actual data. There are no manual overrides.

| Item | Checked when |
| ---- | ------------ |
| Primary assets defined | At least one data asset exists |
| Components identified | Any process or data store exists in a blueprint |
| Trust boundaries identified | Any zone exists in a blueprint |
| Data flows defined | Any flow exists in a blueprint |
| Threats linked to components and flows | The share of components and flows that have at least one active threat targeting them |
| Countermeasures assigned | The share of active threats that have at least one linked countermeasure |
| Owners assigned | The share of countermeasures that have an assigned owner |

The first four are yes or no. The last three are fractions, shown as a count and a percentage. A model with more than one blueprint counts all of them together.

## How it works

The backend computes the checklist fresh on every request. Nothing is stored or cached. The checkboxes in the UI are read-only and reflect the current state of the threat model data.

Threats triaged as Accept, Delegate, or Eliminate do not count toward the threat items. Only active threats (Open or Mitigate) satisfy those checks. A threat with several targets counts once per target it covers. A countermeasure that is not linked to any threat does not count toward "Countermeasures assigned".

The sign-off view uses one more figure that is not a checklist item: how many assumptions are still unverified. See [Collaborative Review and Handoff](../guides/collaborative-review-and-handoff.md).

The checklist is a model-completeness signal, not a risk-acceptance or compliance signal. For example, "Countermeasures assigned" means that a threat has at least one countermeasure linked to it. It does not mean every countermeasure is implemented, verified, or sufficient to satisfy a compliance requirement.

Countermeasure status, threat mitigation status, residual risk, and compliance satisfaction are related but separate concepts. A countermeasure status describes implementation progress for a control. Threat mitigation status summarizes whether linked controls appear to address a threat. Residual risk estimates the remaining risk after considering available controls. Compliance satisfaction depends on mapped requirements and the statuses counted as satisfying evidence in reports.

When interpreting a report, compare these signals together instead of treating any single checkbox as final evidence. A threat model can be structurally complete while still containing open risks, planned controls, unverified controls, or compliance gaps. Completion status answers "has this part of the model been filled in?" rather than "is this system fully mitigated?"

## Where it appears

The checklist surfaces on the Overview tab, in magic link shared views, and in exported reports.
