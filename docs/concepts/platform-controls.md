# Platform Controls

Platform controls are countermeasures handled at the infrastructure level rather than by individual application teams. They represent security capabilities built into the platform itself, such as WAF filtering, managed encryption, or network segmentation. Only [Security Team](roles-and-permissions.md) members can assign platform status.

## Platform vs verified

Both platform and verified fully mitigate a threat and are treated as 100% effective in risk scoring. The difference is ownership:

- **Verified**: the application team has confirmed this control is in place.
- **Platform**: this control is provided by infrastructure and managed by the security team.

Platform countermeasures show a lock icon to non-security-team members, who cannot change the status.

![Countermeasure status buttons showing Platform with lock icon](../assets/images/platform-controls-status-buttons.png)

## How controls become platform

There are two paths, plus import:

### Library pack defaults

Pack authors can set `default_status: platform` on a countermeasure definition. When that countermeasure is added to any component, it starts as platform automatically.

```yaml
countermeasures:
  - id: apigw-waf
    name: API Gateway WAF Integration
    description: |
      Enable AWS WAF to protect against common web exploits.
      Block SQL injection, XSS, and known bad actors.
    control_functions:
      - preventive
    control_nature: technical
    cost: medium
    default_status: platform
```

If `default_status` is omitted, countermeasures default to `gap`.

### Manual assignment

Security Team members can click the **Platform** button on any countermeasure in the Threat Analysis view. Regular team members do not see this option.

### Import

A CycloneDX TM-BOM file can carry a control with platform status. The import keeps it only when the importing user is on the Security Team. Otherwise the control is stored as a gap and the import summary says so.

## Control scope and provider

Every countermeasure records where it applies and who provides it. Both are shown in the countermeasure detail, exported, and have no effect on any threat's status.

- **Applies to** lists the components, flows, zones, and boundaries the control covers. An empty list means the whole system. Edit it from the countermeasure card; the list is preset from where you added the control.
- **Implemented by** (under Advanced) names the components that implement the control, and optionally another party as text, for example a cloud provider or a platform team.
- **Source** (under Advanced) is free text saying where the control came from, such as a compliance tool or a pentest report.

A control counts for a threat only when it is linked to that threat. A platform WAF scoped to the DMZ zone is a statement about the WAF; it does not close a gap on a threat in that zone until someone links it. This replaces the former zone protection inheritance, which promoted inner-zone gaps to platform automatically.

When a diagram change removes the last target of a scoped control, the control is kept and now applies to the whole system. The editor shows a warning naming the control so you can decide what to do with it.

## Effect on threat status

A threat's status is determined by its countermeasures:

| Countermeasure statuses | Threat status |
| ----------------------- | ------------- |
| All verified or platform | **Mitigated** |
| Mix of planned/waived, no gaps | **Addressable** |
| Any gaps present | **Exposed** |

A single gap countermeasure makes a threat exposed, regardless of how many platform or verified controls are in place.

## Who can manage platform controls

Only users with the **Security Team** organization role can assign or remove platform status. Regular team members (Lead, Member, Viewer) see a lock icon next to platform countermeasures and cannot modify them.

This creates a separation of concerns: security teams define and manage infrastructure-level protections, while application teams focus on the remaining gaps within their threat models.
