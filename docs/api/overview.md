# API Overview

Precogly exposes a REST API built with Django REST Framework. All endpoints are documented with an OpenAPI schema and can be explored interactively via Swagger UI.

## Base URL

All endpoints are prefixed with `/api/`:

```
http://localhost:8000/api/
```

## Content format

**Request and response bodies use JSON with camelCase keys.** The backend uses snake_case internally, but `djangorestframework-camel-case` converts keys automatically at the API boundary.

```json
{
  "threatModel": {
    "id": 1,
    "name": "Payment Gateway",
    "riskScoringMethod": "qualitative-matrix",
    "createdAt": "2026-01-15T10:30:00Z"
  }
}
```

A small set of keys are passed through without conversion for `dj-rest-auth` compatibility: `password1`, `password2`, `new_password1`, `new_password2`, `email`.

## Authentication

The API uses JWT bearer tokens via `djangorestframework-simplejwt`.

### Obtaining tokens

```
POST /api/auth/login/
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "yourpassword"
}
```

Response:

```json
{
  "accessToken": "eyJ...",
  "refreshToken": "eyJ...",
  "user": {
    "pk": 1,
    "email": "user@example.com"
  }
}
```

### Using tokens

Include the access token in the `Authorization` header:

```
Authorization: Bearer eyJ...
```

### Token lifetimes

| Token | Lifetime |
|-------|----------|
| Access token | 60 minutes |
| Refresh token | 7 days |

Refresh tokens rotate on each use. The previous refresh token is blacklisted after rotation.

### Refreshing tokens

```
POST /api/auth/token/refresh/

{
  "refresh": "eyJ..."
}
```

### Auth endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login/` | Obtain access and refresh tokens |
| `POST` | `/api/auth/logout/` | Blacklist refresh token |
| `POST` | `/api/auth/registration/` | Register a new account |
| `GET` | `/api/auth/user/` | Current user profile |
| `PUT/PATCH` | `/api/auth/user/` | Update profile |
| `POST` | `/api/auth/password/change/` | Change password |
| `POST` | `/api/auth/password/reset/` | Request password reset email |
| `POST` | `/api/auth/password/reset/confirm/` | Confirm password reset |
| `POST` | `/api/auth/token/refresh/` | Refresh access token |

## Pagination

Responses that return lists use page-based pagination with a default page size of **20**.

```json
{
  "count": 58,
  "next": "http://localhost:8000/api/threat-models/?page=2",
  "previous": null,
  "results": [...]
}
```

Use the `page` query parameter to navigate: `?page=2`, `?page=3`, etc.

Some endpoints (library browsing, scoring methods) disable pagination and return all results directly.

## Filtering, search, and ordering

Three filter backends are enabled globally:

- **DjangoFilterBackend** for field-level filtering: `?criticality=high&status=exposed`
- **SearchFilter** for text search: `?search=payment`
- **OrderingFilter** for sorting: `?ordering=-created_at`

Available filter fields vary by endpoint. Refer to the OpenAPI schema for each endpoint's supported parameters.

## Permissions

The API uses two levels of role-based access control. See [Roles and Permissions](../concepts/roles-and-permissions.md) for full details.

**Organization roles** determine broad access:

- **Security Team** has full read/write access across the organization, including library pack management and platform control assignments.
- **Member** has read access across accessible teams, write access only within teams they belong to (with a non-viewer team role).

**Team roles** (Lead, Member, Viewer) control write access to a team's threat models and related data. Viewers are read-only.

All endpoints require authentication by default. The only exceptions are magic link access (`/api/share/{token}/`) and invitation preview (`GET /api/invite/{token}/`).

## Interactive documentation

| URL | Format |
|-----|--------|
| `/api/docs/` | Swagger UI |
| `/api/redoc/` | ReDoc |
| `/api/schema/` | Raw OpenAPI 3.0 schema (YAML) |

The generated OpenAPI documentation is the canonical, exhaustive reference for request
fields, response schemas, filters, and status codes. The tables below provide a practical
map of the public resources and custom actions.

## Endpoint reference

### Threat models

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/threat-models/` | List threat models |
| `POST` | `/api/threat-models/` | Create threat model |
| `GET` | `/api/threat-models/{id}/` | Retrieve threat model |
| `PUT/PATCH` | `/api/threat-models/{id}/` | Update threat model |
| `DELETE` | `/api/threat-models/{id}/` | Delete threat model |
| `GET` | `/api/threat-models/{id}/threats/` | Aggregated threat analysis |
| `GET` | `/api/threat-models/{id}/report/` | Full report data |
| `GET` | `/api/threat-models/{id}/delete_preview/` | Preview cascade before deletion |
| `POST` | `/api/threat-models/{id}/add_referenced_model/` | Add a model relationship (`referenced_model_id`, `relation_type`: `depends_on`, `subsystem_of`, `related_to`, `superseded_by`) |
| `POST` | `/api/threat-models/{id}/remove_referenced_model/` | Remove a model relationship (same fields) |
| `POST` | `/api/threat-models/{id}/generate-threats/` | Add every missing library threat across all blueprints; returns `{created, targets}` |
| `GET` | `/api/threat-models/{id}/review/` | Review and approval state: `approval_state` (`none`, `approved`, `changed`, `review_due`), reviewer, approver, dates, validity fields, the source document's review block |
| `POST` | `/api/threat-models/{id}/mark-reviewed/` | Record the caller as reviewer |
| `POST` | `/api/threat-models/{id}/approve/` | Approve the model and store its content digest (Security Team only) |
| `POST` | `/api/threat-models/{id}/revoke-approval/` | Revoke the approval (Security Team only) |
| `POST` | `/api/threat-models/{id}/add_pack/` | Attach a library pack |
| `POST` | `/api/threat-models/{id}/remove_pack/` | Detach a library pack |
| `GET` | `/api/threat-models/{id}/countermeasures-in-use/` | List countermeasures active in the model |
| `GET` | `/api/threat-models/{id}/compliance_drift/` | Compare instance mappings with their library sources |
| `POST` | `/api/threat-models/{id}/refresh_compliance/` | Refresh instance compliance mappings from libraries |
| `POST` | `/api/threat-models/import/cyclonedx/` | Import a CycloneDX 2.0 TM-BOM file (multipart `file` or a JSON body); returns the new model and a summary with counts and warnings |
| `GET` | `/api/threat-models/{id}/export/cyclonedx/` | Export as CycloneDX 2.0 TM-BOM JSON (the only export format) |

The threat model detail carries `primary_system`, `primary_system_name`, `methodologies`, `lifecycle_phase`, `valid_from`, `valid_until`, `review_frequency`, read-only `approved_at`, `serial_number` and `version`, `blueprints`, and `related_models` (each with `relation_type`, `direction`, and the other model). `risk_scoring_method` is one of `qualitative-matrix`, `owasp-risk-rating`, `fair`, `mozilla-rra`; it cannot change while the model has risks.

**Blueprints** (nested under threat model):

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/api/threat-models/{id}/blueprints/` | List or create blueprints (`name`, `description`, `model_types`, `scope_description`) |
| `GET/PUT/PATCH/DELETE` | `/api/threat-models/{id}/blueprints/{id}/` | Retrieve, update, or delete; the last blueprint cannot be deleted |
| `GET` | `/api/threat-models/{id}/blueprints/{id}/delete_preview/` | What a delete removes: counts per row type, threats deleted, threats that lose targets |

**Assumptions, business objectives, use cases** (nested under threat model):

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/api/threat-models/{id}/assumptions/` | List or create (`description`, `topic`, `validity`, `impact`, `owner`, `owner_name`, `validation_method`, `validation_date`, `component_ids`; `blueprint` defaults to the model's first). Filters: `blueprint`, `validity`, `topic` |
| `GET/PUT/PATCH/DELETE` | `/api/threat-models/{id}/assumptions/{id}/` | Retrieve, update, or delete |
| `GET/POST` | `/api/threat-models/{id}/business-objectives/` | List or create (`name`, `description`, `criticality`, `owner`, `owner_name`); each carries threat and risk counts |
| `GET/PUT/PATCH/DELETE` | `/api/threat-models/{id}/business-objectives/{id}/` | Retrieve, update, or delete |
| `GET` | `/api/threat-models/{id}/use-cases/` | List use cases that arrived with an import (read-only) |
| `GET/DELETE` | `/api/threat-models/{id}/use-cases/{id}/` | Retrieve or delete |

**Reference images** (nested under threat model):

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/threat-models/{id}/reference-images/` | List images |
| `POST` | `/api/threat-models/{id}/reference-images/upload/` | Upload image (multipart) |
| `DELETE` | `/api/reference-images/{id}/` | Delete image |

**Out-of-scope items** (nested under threat model):

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/api/threat-models/{id}/out-of-scope-items/` | List or create |
| `GET/PUT/PATCH/DELETE` | `/api/threat-models/{id}/out-of-scope-items/{id}/` | Retrieve, update, or delete |

Out-of-scope items take an optional `blueprint` and default to the model's first.

### Diagrams

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/diagrams/` | List DFDs |
| `POST` | `/api/diagrams/` | Create DFD |
| `GET` | `/api/diagrams/{id}/` | Retrieve DFD with canvas data |
| `PUT/PATCH` | `/api/diagrams/{id}/` | Update DFD (triggers sync for the blueprint's primary DFD; the response carries `sync_warnings` when a control lost its last target) |
| `DELETE` | `/api/diagrams/{id}/` | Delete DFD |
| `POST` | `/api/diagrams/create_for_threat_model/` | Create DFD from template for a threat model (`blueprint_id` or `threat_model_id`) |
| `GET` | `/api/diagrams/ai-availability/` | Check whether AI diagram generation is configured |
| `POST` | `/api/diagrams/analyze-image/` | Analyze an uploaded architecture image |
| `POST` | `/api/diagrams/generate-dfd/` | Generate DFD canvas data from an analyzed image |
| `GET` | `/api/diagrams/{id}/delete_preview/` | Preview cascade before deletion |

**DFD templates** (read-only):

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/dfd-templates/` | List templates |
| `GET` | `/api/dfd-templates/{id}/` | Template detail |
| `GET` | `/api/dfd-templates/{id}/resolved/` | Template with component library references resolved |

### Systems and components

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/api/systems/` | List or create systems; each carries `primary_model_count` and `linked_component_count` |
| `GET/PUT/PATCH/DELETE` | `/api/systems/{id}/` | System CRUD; the detail lists `primary_models`. Deleting a system that is some model's primary system returns `409` naming the models |
| `GET/POST` | `/api/components/` | List or create components (`blueprint`, `zone`, `kind`, read-only `effective_kind`). Filters: `threat_model`, `blueprint`, `kind` |
| `GET/PUT/PATCH/DELETE` | `/api/components/{id}/` | Component CRUD |
| `POST` | `/api/components/{id}/generate_threats/` | Generate threats from component library |
| `GET/POST` | `/api/component-library/` | Browse or create library components |
| `GET/PUT/PATCH/DELETE` | `/api/component-library/{id}/` | Library component CRUD |

### Zones and boundaries

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/api/zones/` | List or create zones (`blueprint`, `zone_type`, `trust_level` 0 to 100 or null, `parent`). Filters: `threat_model`, `blueprint`, `zone_type` |
| `GET/PUT/PATCH/DELETE` | `/api/zones/{id}/` | Zone CRUD |
| `GET/POST` | `/api/boundaries/` | List or create boundaries (`blueprint`, `zone_a`, `zone_b`, `boundary_type`, `authentication` and `authorization` lists, `data_validation`, `data_transformation`, `logging`, `monitoring`, `rate_limit`, `protocols`, `session_management`; read-only `requires_authentication`, `requires_authorization`). Filters: `threat_model`, `blueprint`, `boundary_type` |
| `GET/PUT/PATCH/DELETE` | `/api/boundaries/{id}/` | Boundary CRUD |

A list that holds `none` beside other values is rejected with `400`.

### Data assets and flows

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/api/data-assets/` | List or create data assets (`blueprint`) |
| `GET/PUT/PATCH/DELETE` | `/api/data-assets/{id}/` | Data asset CRUD |
| `GET/POST` | `/api/flows/` | List or create flows (`blueprint` defaults to the source component's; `flow_type`, `authentication` and `authorization` lists; read-only `requires_authentication`, `crosses_boundary`). Filters: `threat_model`, `blueprint`, `flow_type`, `crosses_boundary` |
| `GET/PUT/PATCH/DELETE` | `/api/flows/{id}/` | Flow CRUD |
| `GET/POST` | `/api/component-data-assets/` | Link data assets to components |
| `GET/POST` | `/api/flow-assets/` | Link data assets to flows (`flow`) |
| `GET/POST` | `/api/integrations/` | List or create integration sources |
| `GET/PUT/PATCH/DELETE` | `/api/integrations/{id}/` | Integration source CRUD |

### Threats

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/api/threat-library/` | Browse or create library threats |
| `GET/PUT/PATCH/DELETE` | `/api/threat-library/{id}/` | Library threat CRUD |
| `GET/POST` | `/api/component-library-threats/` | Map library threats to library components |
| `GET/POST` | `/api/threats/` | List or create threats. One table for every scenario: `number` and `display_number` (`T7`, read-only), `whole_system`, `targets` (read as `[{type, id, name, blueprint_id}]`, written as `[{type, id}]` with `type` in `component`, `flow`, `zone`, `boundary`), `rating` (read) and `rating_inputs` (write), `actor_persona` or `threat_actor_text` (never both), `business_objective_ids`, `auto_generated` (read-only). Filters: `threat_model`, `threat_library`, `status`, `triage_status`, `rating__level`, `number`, `whole_system`, `component`, `flow`, `zone`, `boundary`, `blueprint`; `search` matches the name or `T7` |
| `GET/PUT/PATCH/DELETE` | `/api/threats/{id}/` | Threat CRUD |
| `GET` | `/api/threats/{id}/suggested_countermeasures/` | Countermeasure suggestions from library |
| `POST` | `/api/threats/{id}/apply_countermeasure/` | Apply a library countermeasure |
| `POST` | `/api/threats/{id}/recalculate_status/` | Recalculate threat status |
| `POST` | `/api/threats/{id}/set_targets/` | Replace the target list; an empty list needs `whole_system: true` |
| `POST` | `/api/threats/reorder/` | Reorder threats (optional `target_type` and `target_id` for a per-target order) |
| `GET` | `/api/threats/ai_availability/` | Check AI suggestion availability |
| `POST` | `/api/threats/suggest/` | Get AI-ranked threat suggestions (`target_type`, `target_id`) |
| `GET` | `/api/threat-taxonomy-entries/` | Taxonomy entries on threats; filter `threat` |

### Countermeasures

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/api/countermeasure-library/` | Browse or create library countermeasures |
| `GET/PUT/PATCH/DELETE` | `/api/countermeasure-library/{id}/` | Library countermeasure CRUD |
| `GET/POST` | `/api/countermeasures/` | List or create countermeasures: `number` and `display_number` (`C3`), `targets` (scope, same shape as on threats; empty means the whole system), `implemented_by` (component ids), `implemented_by_party`, `source`, `days_overdue`, `auto_generated`. Filters include `number` and `overdue=true`. Setting or removing `platform` status needs the Security Team role (`403` otherwise) |
| `GET/PUT/PATCH/DELETE` | `/api/countermeasures/{id}/` | Countermeasure CRUD |
| `POST` | `/api/countermeasures/{id}/set_targets/` | Replace the scope |
| `POST` | `/api/countermeasures/{id}/link/` | Link a countermeasure to a threat (`threat_id`) |
| `POST` | `/api/countermeasures/{id}/unlink/` | Unlink a countermeasure from a threat (`threat_id`) |
| `POST` | `/api/countermeasures/reorder/` | Reorder countermeasures within a threat (`threat_id`) |
| `GET/POST` | `/api/countermeasure-comments/` | List or create countermeasure history entries |
| `GET/PUT/PATCH/DELETE` | `/api/countermeasure-comments/{id}/` | Countermeasure comment CRUD |
| `GET/POST` | `/api/verification-tests/` | List or create verification tests |
| `GET/PUT/PATCH/DELETE` | `/api/verification-tests/{id}/` | Verification test CRUD |
| `GET/POST` | `/api/pentest-findings/` | List or create pentest findings |
| `GET/PUT/PATCH/DELETE` | `/api/pentest-findings/{id}/` | Pentest finding CRUD |

### Compliance

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/api/frameworks/` | List or create compliance frameworks |
| `GET/PUT/PATCH/DELETE` | `/api/frameworks/{id}/` | Framework CRUD |
| `GET/POST` | `/api/requirements/` | List or create standard requirements |
| `GET/PUT/PATCH/DELETE` | `/api/requirements/{id}/` | Requirement CRUD |
| `GET/POST` | `/api/countermeasure-standards/` | Library-level compliance mappings |

### Taxonomies

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/taxonomies/` | List taxonomies (STRIDE, CAPEC, CWE, etc.) |
| `GET` | `/api/taxonomies/{id}/` | Taxonomy detail |
| `GET` | `/api/taxonomy-entries/` | List taxonomy entries |
| `GET` | `/api/taxonomy-entries/{id}/` | Entry detail |

### Risk management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/api/threat-models/{id}/risks/` | List or create risks: `status`, `statement`, read-only `exposure`, `domains`, `business_objective_ids`, `threat_ids`, `rating_inputs` (required on create), read-only `inherent`, `residual`, `target`, nested `responses`. Filters: `status`, `inherent__level`, `residual__level`; ordering by `inherent_rank`, `residual_rank`, scores |
| `GET/PUT/PATCH/DELETE` | `/api/threat-models/{id}/risks/{id}/` | Risk CRUD |
| `POST` | `/api/threat-models/{id}/risks/{id}/recalculate/` | Recalculate the residual rating |
| `POST` | `/api/threat-models/{id}/risks/{id}/add-threats/` | Link threats to a risk (`threat_ids`) |
| `POST` | `/api/threat-models/{id}/risks/{id}/remove-threats/` | Unlink threats from a risk (`threat_ids`) |
| `POST` | `/api/threat-models/{id}/risks/bulk-update/` | Bulk update risk `status` or `owner` |
| `GET/POST` | `/api/threat-models/{id}/risks/{id}/responses/` | List or create responses (`strategy`, `description`, `status`, `effectiveness`, `cost`, `priority`, `owner`, `target_date`, `countermeasure_ids`) |
| `GET/PUT/PATCH/DELETE` | `/api/threat-models/{id}/risks/{id}/responses/{id}/` | Response CRUD |
| `GET` | `/api/scoring-methods/` | List risk scoring methods (`key`, `label`, `description`, `input_schema`, `score_scale`, `available`) |

Ratings are read as nested objects (`methodology`, `level`, `score`, `likelihood`, `impact`, `rationale`) and written through `rating_inputs`: a `level` alone, the qualitative matrix's likelihood and impact, or the OWASP factors, plus optional impact categories and quantification.

### Threat personas and sources

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/api/threat-models/{id}/threat-personas/` | List or create threat personas for a model |
| `GET/PUT/PATCH/DELETE` | `/api/threat-models/{id}/threat-personas/{id}/` | Threat persona CRUD |
| `GET` | `/api/threat-sources/` | List global threat source reference data |
| `GET` | `/api/threat-sources/{id}/` | Threat source detail |

### Organizations and teams

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/api/organizations/` | List or create organizations |
| `GET/PUT/PATCH/DELETE` | `/api/organizations/{id}/` | Organization CRUD |
| `GET` | `/api/organizations/{id}/members/` | List organization members |
| `POST` | `/api/organizations/{id}/add-member/` | Add member to organization |
| `POST` | `/api/organizations/{id}/remove-member/` | Remove member from organization |
| `GET/POST` | `/api/teams/` | List or create teams |
| `GET/PUT/PATCH/DELETE` | `/api/teams/{id}/` | Team CRUD |
| `GET` | `/api/teams/{id}/members/` | List team members |
| `POST` | `/api/teams/{id}/add-member/` | Add member to team |
| `POST` | `/api/teams/{id}/invite-member/` | Send team invitation |
| `POST` | `/api/teams/{id}/remove-member/` | Remove member from team |
| `POST` | `/api/teams/{id}/change-member-role/` | Change a member's team role |
| `POST` | `/api/teams/{id}/join/` | Join a team (via invitation) |
| `GET/POST` | `/api/business-units/` | Business unit CRUD |
| `GET/POST` | `/api/memberships/` | Organization membership CRUD |

### Invitations and sharing

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/api/team-invitations/` | List or create invitations |
| `POST` | `/api/team-invitations/{id}/revoke/` | Revoke a pending invitation |
| `GET/POST` | `/api/magic-links/` | List or create magic links |
| `POST` | `/api/magic-links/{id}/revoke/` | Revoke a magic link |
| `GET` | `/api/shared-with-me/` | List threat models shared with current user |
| `DELETE` | `/api/shared-with-me/{id}/remove/` | Remove from shared list |
| `GET` | `/api/share/{token}/` | Access a shared threat model (no auth required) |
| `GET` | `/api/invite/{token}/` | Preview invitation details (no auth required) |
| `POST` | `/api/invite/{token}/` | Accept invitation (auth required) |

### Library packs

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/packs/` | List imported packs |
| `GET` | `/api/packs/{id}/` | Pack detail |
| `GET` | `/api/packs/{id}/preview/` | Preview pack contents |
| `GET` | `/api/packs/{id}/check_dependencies/` | Check dependency status |
| `DELETE` | `/api/packs/{id}/unimport/` | Unimport a pack (Security Team only) |
| `GET` | `/api/packs/available_from_source/` | Browse packs available for import |
| `GET` | `/api/packs/preview_from_source/` | Preview a pack before importing |
| `POST` | `/api/packs/import_single/` | Import a pack (Security Team only) |
| `POST` | `/api/packs/sync_from_source/` | Sync pack catalog (Security Team only) |
| `POST` | `/api/packs/validate/` | Validate pack YAML (Security Team only) |
| `GET` | `/api/packs/available_overlays/` | List compliance overlays available for a pack |

### Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health/` | Health check |
| `GET` | `/api/dashboard/stats/` | Dashboard statistics |

### AI providers and usage

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET/POST` | `/api/ai-providers/` | List or create organization AI provider configurations |
| `GET/PUT/PATCH/DELETE` | `/api/ai-providers/{id}/` | AI provider configuration CRUD |
| `POST` | `/api/ai-providers/{id}/test-connection/` | Test an AI provider connection |
| `GET` | `/api/ai-usage/summary/` | Organization AI usage summary |

## Changes in this release

Paths and fields renamed or removed by the TM-BOM alignment:

| Removed or renamed | Replacement |
|---|---|
| `/api/component-threats/`, `/api/flow-threats/` | `/api/threats/` |
| `/api/component-threats/suggest/`, `/ai_availability/` | `/api/threats/suggest/`, `/api/threats/ai_availability/` |
| `/api/trust-zones/` | `/api/zones/` |
| `/api/trust-boundaries/` | `/api/boundaries/` |
| `/api/data-flows/`, `/api/data-flow-assets/` | `/api/flows/`, `/api/flow-assets/` |
| `/api/threat-models/{id}/zone_protections/`, `/apply_zone_protections/` | Removed |
| `/api/threat-models/{id}/add_system/`, `/remove_system/`, `system_ids` | `primary_system` on the model |
| `/api/components/{id}/assign_system/` | Removed; a component's system is its enclosing system asset |
| `/api/threat-models/import/tm-library/`, `/export/tm-library/` | Removed; CycloneDX TM-BOM is the one format |
| `threat_type` on countermeasure `link`, `unlink`, `reorder` | `threat_id` only |
| `component_threat_ids`, `flow_threat_ids` on risk actions | `threat_ids` |
| `?component_threat=`, `?flow_threat=` on taxonomy entries | `?threat=` |
| Risk `response`, bulk update of `response` | Risk `status`; `/risks/{id}/responses/` |
| Threat `inherent_severity`, `residual_severity`, `severity_scoring_metadata` | `rating`, `rating_inputs` |
| Risk score and level columns, `scoring_metadata` | `inherent`, `residual`, `target`, `rating_inputs` |
| Model `scope_locked`, `scope_locked_at`, `assumptions` | The review endpoints; `/assumptions/` |
| Countermeasure `is_inherited`, `inherited_from_*` | `targets`, `implemented_by`, `implemented_by_party`, `source` |
| Report keys `component_threats`, `data_flow_threats`, `trust_zones`, `trust_boundaries`, `data_flows`, `inherited`, `total_inherited` | `threats`, `zones`, `boundaries`, `flows`; `unattached` and `total_unattached` are new |
| `risk_scoring_method` values `tm_library`, `owasp_rr`, `mozilla_rra`, `custom` | `qualitative-matrix`, `owasp-risk-rating`, `fair`, `mozilla-rra` |
| Flow `authenticated` (boolean) | `authentication` and `authorization` lists |
| Boundary `authentication`, `authorization`, `rate_limiting` (booleans) | `authentication` and `authorization` lists, `rate_limit` text |
| `format_metadata` writable | Read-only everywhere |
| Persona links on threats | `actor_persona` on the threat |

Every row of a threat model's structure (components, zones, boundaries, flows, data assets, diagrams, assumptions, out-of-scope items) now carries a `blueprint`; `?threat_model=` and `?blueprint=` narrow the lists.

## Error responses

The API returns standard HTTP status codes:

| Code | Meaning |
|------|---------|
| `400` | Bad request. Validation errors are returned as a JSON object with field names as keys. |
| `401` | Authentication required or token expired. |
| `403` | Insufficient permissions for this action. |
| `404` | Resource not found. |
| `405` | Method not allowed. |
| `409` | Conflict. Deleting a system that is a model's primary system returns the models that use it. |

Validation error example:

```json
{
  "name": ["This field is required."],
  "criticality": ["\"invalid\" is not a valid choice."]
}
```

## Multi-tenancy

All data is scoped to the authenticated user's organization memberships. Queries automatically filter to organizations the user belongs to. There is no way to access data from organizations you are not a member of.
