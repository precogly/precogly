# Precogly

## The open-source alternative to commercial threat modeling platforms

!!! success "v0.4.0 Released"
    Precogly v0.4.0 is now available. See the [changelog](changelog.md) for details, or [download the release on GitHub](https://github.com/precogly/precogly/releases/tag/v0.4.0).

Open-source threat modeling tools lack enterprise features. Commercial tools come with heavy price tags and vendor lock-in. Precogly bridges this gap and democratizes threat modeling for every organization in the world.

<div style="text-align: center;" markdown>
  <iframe width="720" height="405" src="https://www.youtube.com/embed/5sSuZOAtyn4" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
</div>

## Key Features

- **CycloneDX 2.0 TM-BOM import and export**: one interchange format, validated against the CycloneDX schema, for moving models between Precogly and other tools
- **Collaborative workspaces** — team collaboration for threat modeling programs
- **Advanced DFD editor**: nested components, typed zones, boundaries and flows, numbered threats and controls, and more
- **Community library packs** — links to MITRE ATT&CK, CAPEC, LINDDUN, STRIDE, and other taxonomies for high-quality threat models

## Who is Precogly for?

- **Security architects** looking to scale threat modeling across their organizations
- **Security engineers** who need a well-architected foundation for AI-powered threat modeling assistants
- **Threat modeling consultants and trainers** looking for a platform that supports reference images, team collaboration, and structured programs
- **Compliance professionals** looking to link threat modeling with standards like ASVS or regulations like CRA and DORA

## How is Precogly different?

- **Compliance-aware** — built-in traceability to DORA, CRA, ASVS, NIST CSF, SOC 2, and more
- **Structured library packs** — curated packs with components, threats, countermeasures, and taxonomy links
- **AI-agent ready architecture** — a clean REST API with full OpenAPI docs
- **Pack ecosystem** — community and official packs for AWS, Azure, GCP, banking, and compliance frameworks

## Quick Start

```bash
git clone --branch v0.4.0 https://github.com/precogly/precogly.git
cd precogly
docker compose up --build
```

Open [http://localhost:5173](http://localhost:5173) and log in with `admin@precogly.dev` / `admin123`. Two further demo accounts are seeded so roles and multi-tenancy can be exercised locally; the seed prints all three when it finishes.

## Tech Stack

| Layer          | Technology                                          |
| -------------- | --------------------------------------------------- |
| **Frontend**   | React 19, TypeScript, Tailwind CSS, shadcn/ui, React Flow |
| **Backend**    | Django 5.1, Django REST Framework, PostgreSQL 16     |
| **Infrastructure** | Docker, nginx (production)                      |

## Next Steps

- [Installation](getting-started/installation.md) — detailed setup instructions
- [Quickstart](getting-started/quickstart.md) — create your first threat model
- [Concepts](concepts/library-packs.md) — understand Precogly's core concepts
