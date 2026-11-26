# Bundled demo packs

This folder holds the three small demo packs that ship inside Precogly. The full library of packs lives in a separate repository: [precogly/library-packs](https://github.com/precogly/library-packs). New packs and changes to full packs go there, not here.

## The three demo packs

```
libraries/packs/
├── demo-taxonomies/stride-taxonomy
├── demo-standards/demo-asvs
└── demo-threat-libraries/demo-aws
```

- **stride-taxonomy.** The real STRIDE taxonomy pack, unchanged. Its slug stays `stride-taxonomy`.
- **demo-asvs.** Pack slug `demo-asvs`, framework slug `demo-asvs-4`, display name "Demo: OWASP ASVS subset". It has 44 of the 278 OWASP ASVS 4.0.3 requirements: 33 that `demo-aws` maps to, plus 11 that nothing maps to, so the compliance matrix shows gaps.
- **demo-aws.** Pack slug `demo-aws`, name "Demo: AWS". It has 10 components (API Gateway, CloudFront, Cognito, DynamoDB, IAM, KMS, Lambda, RDS, S3, WAF), 45 threats, 58 countermeasures, mappings to STRIDE and the demo ASVS only, and two templates: "Demo: Serverless Web Application" and "Demo: SaaS Tenant Isolation".

The `seed` command imports these three packs and creates two sample threat models. These packs are edited here, in this repository.

## Naming rules

1. STRIDE keeps its real slug because app code uses the taxonomy name `stride`.
2. The demo ASVS has its own slugs, so importing the full ASVS from the library adds a second standard instead of replacing the demo one.

## Item IDs match the full AWS pack

Item IDs in `demo-aws` match the full `aws` pack. Only the pack prefix differs: S3 is `demo-aws/s3` here and `aws/s3` in the full pack.

## Writing a pack

The authoring guide is in the library-packs repository: [docs/authoring-guide.md](https://github.com/precogly/library-packs/blob/main/docs/authoring-guide.md). The catalog format is in [docs/catalog-format.md](https://github.com/precogly/library-packs/blob/main/docs/catalog-format.md). To try a pack locally against this app, see [Creating library packs](../docs/contributing/creating-library-packs.md).

## Attribution

`demo-asvs` is adapted from OWASP ASVS 4.0.3, (c) 2008-2021 The OWASP Foundation, CC BY-SA 3.0.
