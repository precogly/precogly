# EU Banking: Unified Regulatory Compliance

Commonly used in: Retail Banking, Investment Banking, Payment Services, Insurance, Fintech

This recipe shows how to threat model systems in an EU-regulated financial institution using Precogly. It covers how to layer multiple compliance frameworks (DORA, PSD2, GDPR, PCI DSS, NIST CSF) into a single threat model and read the unified compliance picture.

---

## The regulatory landscape

EU banks operate under overlapping regulatory obligations. A single system can be subject to multiple frameworks simultaneously:

| Regulation / Standard | Scope | Enforced By |
|----------------------|-------|-------------|
| **DORA** (Digital Operational Resilience Act) | ICT risk management, incident reporting, resilience testing, third-party risk | ESAs (EBA, EIOPA, ESMA) |
| **PSD2** (Payment Services Directive 2) | Strong customer authentication, secure communication, open banking APIs | National competent authorities |
| **GDPR** (General Data Protection Regulation) | Personal data protection, privacy by design, breach notification | National DPAs |
| **PCI DSS** (Payment Card Industry Data Security Standard) | Cardholder data protection | Card brands / QSAs |
| **NIST CSF** (Cybersecurity Framework) | Baseline cybersecurity posture | Voluntary, but widely expected by supervisors |
| **EBA ICT Guidelines** | ICT and security risk management | EBA / national supervisors |

The challenge is not implementing each framework in isolation. It is demonstrating unified coverage: showing that a single set of security controls satisfies requirements across all applicable frameworks, without duplication of effort.

---

## How it maps to Precogly

| Banking need | Precogly feature |
|-------------|------------------|
| Multiple overlapping regulations | Link multiple compliance frameworks to a single threat model |
| Cross-framework control mapping | One countermeasure maps to requirements across DORA, PCI DSS, and GDPR simultaneously |
| Proportionality (DORA tiers) | Separate compliance framework per tier, same pattern as IEC 62443 security levels |
| System-specific obligations | Link only the frameworks relevant to each threat model |
| Audit evidence | Compliance tab shows requirement satisfaction with countermeasure status |
| Third-party risk (DORA) | Related threat models with a "depends on" link to each provider's model |
| System inventory | Each model names its primary system; the Systems page shows which systems have a model |

---

## Which packs to import

Import these packs in order (dependencies first):

**Taxonomy packs:**

| Pack | Purpose |
|------|---------|
| `stride-taxonomy` | STRIDE threat classification |
| `cwe` | CWE weakness enumeration |
| `capec` | CAPEC attack patterns |
| `mitre-attack` | MITRE ATT&CK Enterprise techniques |

**Compliance packs:**

| Pack | Purpose |
|------|---------|
| `dora` | DORA requirements, split by proportionality tier |
| `psd2` | PSD2 strong authentication and secure communication requirements |
| `gdpr` | GDPR data protection requirements |
| `pci-dss` | PCI DSS cardholder data requirements |
| `nist-csf` | NIST CSF baseline cybersecurity requirements |

**Technology and threat packs:**

| Pack | Purpose |
|------|---------|
| `banking` | Banking-specific components, threats, and countermeasures |
| `aws` or `azure` | Cloud infrastructure (if applicable) |

!!! tip
    You do not need all compliance packs for every threat model. Import them all into the organization once, then link only the relevant ones to each threat model.

---

## Structuring the DORA compliance pack

DORA applies proportionality: requirements scale based on the entity's size, risk profile, and whether it is classified as a critical ICT third-party provider. Use the same per-tier pattern as the [IEC 62443 recipe](iec-62443.md):

```yaml
# dora/pack.yaml
pack:
  slug: dora
  name: "DORA"
  version: "1.0.0"
  pack_type: compliance
  description: "Digital Operational Resilience Act (EU 2022/2554)"

frameworks:
  - slug: dora-base
    name: "DORA Base Requirements"
    version: "2022/2554"
    issuer: "European Parliament"
    description: "Core ICT risk management requirements applicable to all financial entities"
    requirements:
      - section_code: "Art 5.1"
        description: "Establish and maintain an ICT risk management framework"
      - section_code: "Art 6.1"
        description: "Identify and classify all ICT-supported business functions and assets"
      - section_code: "Art 7.1"
        description: "Implement ICT systems and tools to minimize the impact of ICT risk"
      # ... core requirements

  - slug: dora-enhanced
    name: "DORA Enhanced Requirements"
    version: "2022/2554"
    issuer: "European Parliament"
    description: "Additional requirements for entities not qualifying for the simplified framework"
    requirements:
      - section_code: "Art 8.1"
        description: "Implement policies for network security management"
      - section_code: "Art 9.1"
        description: "Implement detection mechanisms for anomalous activities"
      - section_code: "Art 10.1"
        description: "Establish ICT business continuity policy"
      # ... additional requirements for larger entities

  - slug: dora-critical-ict
    name: "DORA Critical ICT Provider"
    version: "2022/2554"
    issuer: "European Parliament"
    description: "Additional requirements for critical ICT third-party service providers"
    requirements:
      - section_code: "Art 31.1"
        description: "Critical ICT third-party providers subject to oversight framework"
      # ... oversight requirements
```

Setting the target tier works the same way as IEC 62443 security levels:

- **Small fintech qualifying for simplified framework**: link only **DORA Base Requirements**
- **Standard bank**: link **DORA Base** + **DORA Enhanced**
- **Critical ICT provider to banks**: link **DORA Base** + **DORA Enhanced** + **DORA Critical ICT Provider**

---

## Which frameworks to link by system type

Not every system requires every framework. Use this matrix as a starting point:

| System | DORA | PSD2 | GDPR | PCI DSS | NIST CSF |
|--------|------|------|------|---------|----------|
| Payment processing | Yes | Yes | Yes | Yes | Yes |
| Core banking platform | Yes | - | Yes | - | Yes |
| Customer onboarding / KYC | Yes | - | Yes | - | Yes |
| Mobile banking app | Yes | Yes | Yes | - | Yes |
| Open banking API gateway | Yes | Yes | Yes | - | Yes |
| Card issuing / acquiring | Yes | Yes | Yes | Yes | Yes |
| Internal risk analytics | Yes | - | Yes | - | Yes |
| ATM / POS network | Yes | - | - | Yes | Yes |
| Third-party cloud hosting | Yes | - | Yes | - | Yes |

!!! info
    NIST CSF appears everywhere because it provides the baseline cybersecurity posture that regulators expect regardless of specific regulatory obligations. DORA appears everywhere because it applies to all ICT systems within EU financial entities.

---

## Workflow

### 1. Create the threat model

Create a new threat model for the specific system (e.g., "Payment Processing Service", "Mobile Banking App") and choose it as the model's **primary system** from the inventory, creating the inventory entry in place if it does not exist yet. The Systems page under Settings then shows which systems have a model, which supervisors ask for. Set criticality based on business impact:

- **Critical**: payment processing, core banking, authentication services
- **High**: customer-facing applications, open banking APIs
- **Medium**: internal analytics, reporting systems

### 2. Define the system context

Write a system description covering the business function, data processed, and regulatory scope. Define data assets with categories matching the regulatory context:

**Payment processing example:**

| Asset | Category | C | I | A |
|-------|----------|---|---|---|
| Cardholder Data (PAN, CVV) | Financial Data | High | High | High |
| Customer PII | PII | High | High | Medium |
| Transaction Records | Financial Data | High | High | High |
| Authentication Credentials | Credentials / Secrets | High | High | High |
| API Keys and Certificates | Credentials / Secrets | High | High | High |
| Audit Logs | Business Critical | Medium | High | High |

### 3. Link compliance frameworks

Navigate to compliance settings and link the frameworks applicable to this system. For a payment processing service:

1. **DORA Base Requirements**
2. **DORA Enhanced Requirements** (if not qualifying for simplified framework)
3. **PSD2**
4. **GDPR**
5. **PCI DSS**
6. **NIST CSF**

This is the step that defines your compliance scope. The compliance tab will show the combined requirements from all linked frameworks.

### 4. Model the architecture

Use the DFD editor to model the system. If using the banking library pack, components arrive with pre-mapped threats and countermeasures.

Organize components into zones that reflect your network architecture (network zones with a trust level, or trust zones), and draw boundaries where a crossing has requirements such as strong customer authentication:

- **Internet Zone**: customer-facing endpoints, CDN
- **DMZ**: API gateways, WAF, load balancers
- **Application Zone**: application servers, microservices
- **Data Zone**: databases, payment HSMs, key stores
- **Integration Zone**: third-party connections, open banking APIs
- **Management Zone**: admin interfaces, monitoring

### 5. Analyze threats and apply countermeasures

Review threats in the Threat Analysis tab. For each threat, apply countermeasures and track their status. Library countermeasures arrive with compliance mappings already attached across all relevant frameworks.

### 6. Read the unified compliance tab

This is where the multi-framework approach pays off. The compliance tab shows all requirements from all linked frameworks, grouped by framework.

**What to look for:**

A single countermeasure often satisfies requirements across multiple frameworks. For example:

| Countermeasure | DORA | PSD2 | GDPR | PCI DSS |
|---------------|------|------|------|---------|
| TLS 1.2+ encryption in transit | Art 7.1 | Art 22(1) | Art 32(1)(a) | Req 4.1 |
| Multi-factor authentication | Art 9.3 | Art 97(1) | - | Req 8.3 |
| Encryption of data at rest | Art 7.1 | - | Art 32(1)(a) | Req 3.4 |
| Audit logging | Art 12.1 | - | Art 30 | Req 10.1 |
| Incident response plan | Art 17.1 | Art 96(1) | Art 33 | Req 12.10 |

This cross-framework view demonstrates to auditors that your security controls are designed with unified regulatory coverage, not implemented in silos.

**Gap analysis across frameworks:**

- Filter by framework to see coverage for a specific regulation
- Filter by status (Gap, Planned, Verified) to see the remediation roadmap
- A countermeasure in Gap status creates gaps across ALL frameworks it maps to, making it easy to prioritize: fix the countermeasures that close the most gaps across the most frameworks

### 7. Score risks

Aggregate threats into business-level risks that align with your bank's risk taxonomy. Common risk categories for banking:

- **Data breach / unauthorized disclosure**
- **Transaction fraud / payment manipulation**
- **Service unavailability / operational disruption**
- **Regulatory non-compliance**
- **Third-party / supply chain compromise**

Link threats from the threat analysis to these risks, and score using the methodology your risk function requires (often FAIR for financial institutions).

### 8. Third-party risk (DORA Chapter V)

DORA places significant emphasis on ICT third-party risk management. Use Precogly's connected threat models to model this:

1. Create a separate threat model for each critical ICT third-party provider, with the provider's system as its primary system
2. In your system's model, open **Manage Threat Models**, choose **depends on**, and add the provider's model
3. In the provider's threat model, link the **DORA Critical ICT Provider** framework
4. Track the provider's compliance status independently

This gives you a connected view: your system's threat model shows its dependencies, and each dependency has its own compliance tracking. The export carries each dependency as a BOM-Link to the provider's model, so an auditor can follow the chain from one file to the next. See [Systems and Related Threat Models](../concepts/connected-systems-tm.md).

---

## DORA proportionality summary

| Entity type | Which DORA frameworks to link |
|-------------|-------------------------------|
| Micro-enterprise qualifying for simplified framework | DORA Base only |
| Standard financial entity | DORA Base + DORA Enhanced |
| Critical ICT third-party provider | DORA Base + DORA Enhanced + DORA Critical ICT Provider |

The achieved compliance tier is determined the same way as [IEC 62443 security levels](iec-62443.md): the highest tier whose requirements are all satisfied by verified or platform countermeasures.

---

## Audit preparation

When preparing for supervisory examinations or audits:

1. **Export the threat model** as CycloneDX TM-BOM for archival (see [Importing & Exporting](../guides/importing-exporting.md))
2. **Share via magic links** to give auditors read-only access without creating accounts (see [Magic Links](../concepts/magic-links.md))
3. **Use the compliance tab** as evidence of requirement coverage across all applicable frameworks
4. **Reference the risk analysis** to show that threats have been assessed and scored using a recognized methodology

!!! tip
    Auditors value traceability. The chain from component to threat to countermeasure to compliance requirement, visible in a single tool, is significantly more convincing than spreadsheets stitched together from multiple sources.

---

## What's next

- [IEC 62443 Recipe](iec-62443.md): if your bank operates OT/ICS infrastructure (ATMs, building management, trading floor systems)
- [Library Packs](../concepts/library-packs.md): how packs, overlays, and dependencies work
- [Creating Library Packs](../contributing/creating-library-packs.md): build custom packs for your institution's internal standards
- [Creating a Threat Model](../guides/creating-threat-model.md): end-to-end threat modeling workflow
- [Compliance Mapping](../guides/compliance-mapping.md): mapping countermeasures to framework requirements
