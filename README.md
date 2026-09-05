# Precogly

[![Latest Release](https://img.shields.io/github/v/release/precogly/precogly)](https://github.com/precogly/precogly/releases/latest)
[![License](https://img.shields.io/github/license/precogly/precogly)](LICENSE)
[![Stars](https://img.shields.io/github/stars/precogly/precogly)](https://github.com/precogly/precogly/stargazers)
[![Discord](https://img.shields.io/badge/Discord-Join%20Chat-5865F2?logo=discord&logoColor=white)](https://discord.gg/uBFZGJzpYa)
![OWASP Project](https://img.shields.io/badge/OWASP-Project-blue?logo=owasp)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/precogly/precogly/badge)](https://securityscorecards.dev/viewer/?uri=github.com/precogly/precogly)

> [!IMPORTANT]
> **Precogly is now an OWASP project!** OWASP is the world's largest open-source application security community, and Precogly is proud to be part of it.

## The open-source alternative to commercial threat modeling platforms

### Quick Start

```bash
  git clone --branch v0.3.0 https://github.com/precogly/precogly.git
  cd precogly
  docker compose up --build
```

Open http://localhost:5173 and log in with admin@precogly.dev / admin123. Two further demo accounts are seeded so roles and multi-tenancy can be exercised locally; the seed prints all three when it finishes.

### Documentation

[precogly.github.io/precogly](https://precogly.github.io/precogly/)

### Video Walkthrough

[![Precogly Walkthrough](https://img.youtube.com/vi/5sSuZOAtyn4/maxresdefault.jpg)](https://www.youtube.com/watch?v=5sSuZOAtyn4)

### Why Precogly?

Open-source threat modeling tools lack enterprise features. Commercial tools come with heavy price tags and vendor lock-in.

Precogly bridges this gap and democratizes threat modeling for every org in the world.

### Key Features

- Import and export TM-BOM style JSON files - improves interoperability with other threat modeling platforms
- A threat modeling workspace allows for team collaboration
- An advanced DFD editor (allows for nested components, trust zones with trust boundaries and much more)
- Community library packs with links to taxonomies like MITRE ATT&CK, CAPEC, LINDDUN, STRIDE etc. - allows your team to quickly create high quality threat models

### Who is Precogly for?

- **Security architects** looking to scale threat modeling in their orgs.
- **Vibe coding security engineers** who need a well-architected CRUD foundation on which they can build their AI threat modeling assistants.
- **Threat modeling consultants and trainers** looking for a platform that supports reference images, team collaboration, and structured threat modeling programs.
- **Compliance professionals** looking to link threat modeling with security requirements coming from standards like ASVS or laws like CRA and DORA

Precogly is designed for enterprise workflows, but smaller organizations can also find value in the DFD editor, library packs, and collaborative workspace.

### How is Precogly different?

- **Compliance-aware** — Built-in traceability to DORA, CRA, ASVS, NIST CSF, SOC 2, and more. Threats can link to security taxonomies, while countermeasures map to framework requirements.
- **Structured library packs** — Not just brainstorming. Curated packs with components, threats, countermeasures, and taxonomy links (MITRE ATT&CK, CAPEC, CWE, STRIDE) give your team a structured starting point.
- **AI-agent ready architecture** — A clean REST API with full OpenAPI docs, designed to be a foundation for AI-powered threat modeling assistants.
- **Pack ecosystem** — Community and official packs for AWS, Azure, GCP, banking, and compliance frameworks. Extend or create your own.

### Our AI Philosophy

1. **AI agents need CRUD scaffolding** — Before AI generates a single threat, the platform must let you create, store, update, and track its core objects.
2. **Ahead-of-time AI > just-in-time AI** — You can point AI at a system during threat modeling, or use it ahead of time to build curated threat libraries linked to standards. The second wins. Fewer hallucinations, more consistency.
3. **The journey of understanding is the threat model** — The value of the threat model lives in the shared comprehension that humans build along the way. That needs a common interface where humans and agents work from the same picture.

### Tech Stack

- **Frontend:** React 19, TypeScript, Tailwind CSS, shadcn/ui, React Flow
- **Backend:** Django 5.1, Django REST Framework, PostgreSQL 16
- **Infrastructure:** Docker, nginx (production)

### Roadmap

See the [GitHub milestones](https://github.com/precogly/precogly/milestones) for current and upcoming release work.

### Security

To report a vulnerability, please see our [Security Policy](SECURITY.md).

### Contributing

- [Open an issue](https://github.com/precogly/precogly/issues)
- [Contribute a library pack](docs/contributing/creating-library-packs.md)
- Contribute to the codebase

If you find Precogly useful, give the project a star!

### Community

Join the conversation on [Discord](https://discord.gg/uBFZGJzpYa).

### Need Help? Contact the Developer

- [LinkedIn](https://www.linkedin.com/in/vikramadityanarayan/)
- [Email](mailto:vikramsnarayan@gmail.com)
- [Book a call](https://calendly.com/vikramsnarayan/30min)

### Special Thanks

A special thanks to Jeroen Verwoest for generously sharing his knowledge about threat modeling at an enterprise-scale in a compliance-heavy environment.

### License

Apache 2.0
