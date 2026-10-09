"""Projections of Precogly API responses into shapes worth giving a language model.

These are deliberately narrower than what the API returns. The projection for each
tool is argued in docs/0002-tool-implementation-order.md; the reasoning is always
the same shape — a field that costs a traversal per row, or that carries geometry
rather than meaning, is dropped rather than forwarded.

Every model parses camelCase, because `djangorestframework_camel_case` renders the
API that way (`REST_FRAMEWORK["DEFAULT_RENDERER_CLASSES"]` in
`config/settings/base.py`) while the Django source these fields are named after is
snake_case.

Measurements and references into Precogly are against `precogly@c53f4d3`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic.alias_generators import to_camel


class ThreatModelSummary(BaseModel):
    """One row of `GET /api/threat-models/`, as an agent choosing what to open needs it.

    `frameworks` is narrowed to bare names rather than dropped. The three queries per
    row that `ThreatModelFieldsMixin.get_frameworks` costs are the server's either
    way — it is a `SerializerMethodField` in the list serializer's `fields`, so it
    runs whether or not this projection forwards the result. What a projection
    controls is tokens, and on the seeded listing the framework objects cost 68% on
    top of the rest of the row while their names cost 18%.
    """

    # Extra keys are ignored rather than forbidden, which is the one place this model
    # does not fail loudly on an upstream change. It cannot: the projection drops
    # `sourcePack` ids and framework ids by design, so forbidding unknown keys would
    # reject every response.
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    id: int
    name: str

    # Not `str | None`: `description` is NOT NULL in Postgres, so an empty model has
    # `""` here. Typing it optional would model a state the database cannot produce.
    description: str

    # Closed over the choices `OPTIONS /api/threat-models/` reports, so a vocabulary
    # added upstream fails here rather than reaching an agent as a value this projection
    # was never checked against. The failure is deliberately whole-page: one unknown
    # criticality raises rather than degrading a single row, because a listing that
    # silently omits or mangles entries is the harder bug to notice.
    criticality: Literal["low", "medium", "high", "critical"]

    # The next four are optional because the columns behind them are nullable, not
    # because the sample response showed a null. Only `businessUnitName` was null there;
    # `created_by_id` and `owning_team_id` are nullable in the schema, and a response
    # that happens to populate them proves nothing about the ones that will not.
    owner: str | None = Field(
        default=None,
        description="Email of the creating user.",
    )
    owning_team: int | None = None
    owning_team_name: str | None = None
    business_unit_name: str | None = None

    # Names only. The API sends `{"id", "name", "version"}`; the id is a primary key no
    # tool accepts, and the version does not participate in the question this field is
    # asked. Defaulted rather than required because a model whose countermeasures map
    # to nothing has no frameworks, a state the fixture does not show.
    frameworks: list[str] = Field(
        default_factory=list,
        description=(
            "Compliance frameworks this model touches. Incidence, not coverage: a "
            "framework is listed when at least one countermeasure maps to at least one "
            "of its requirements, so a model addressing a single control appears "
            "identically to one addressing every control."
        ),
    )

    risk_scoring_method: Literal[
        "qualitative-matrix", "owasp-risk-rating", "fair", "mozilla-rra"
    ]

    # The summary fields the model-alignment work added (plan section 7).
    # `approved_at` is the approval date, not the approval state, which a list
    # never computes.
    methodologies: list[str] = Field(default_factory=lambda: ["STRIDE"])
    lifecycle_phase: str = ""
    approved_at: datetime | None = None
    primary_system_name: str | None = None
    serial_number: str | None = None
    version: int = 1
    blueprint_count: int = 1

    created_at: datetime
    updated_at: datetime

    @field_validator("frameworks", mode="before")
    @classmethod
    def _names_only(cls, value: object) -> object:
        """Reduce the API's framework objects to the names.

        Left permissive on shape: a value that is not the expected list of objects is
        handed on untouched, so the type error names `frameworks` rather than surfacing
        as a `KeyError` from inside this validator.
        """
        if isinstance(value, list):
            return [
                item["name"] if isinstance(item, dict) and "name" in item else item
                for item in value
            ]
        return value


class ThreatModelListing(BaseModel):
    """What `list_threat_models` answers with: rows, and how many there were.

    A bare list would be shorter and would hide the one thing a caller cannot work
    out for itself. Reading Precogly over its REST API returns a single page and
    cannot ask for another, so an answer of twenty may be twenty of twenty or twenty
    of two hundred, and only `total` separates them. Returning it is the same lesson
    as docs/0005-code-execution-over-tools.md: a decision that looks like it is about
    payload size is usually about which questions remain answerable.
    """

    models: list[ThreatModelSummary]

    total: int = Field(
        description=(
            "How many threat models are visible to you in total. When this exceeds "
            "the number of entries returned, you are seeing the most recently "
            "updated ones and there is no way to request the rest — say so rather "
            "than presenting the list as complete."
        ),
    )


class TaxonomyReference(BaseModel):
    """One nested entry of `taxonomyEntries`, cut to what identifies it.

    The API sends six fields. Three are dropped, each measured on the seeded catalog
    (`tmp/measure_taxonomy_projection.py`): the internal `id`, because no tool exposed
    here takes a `TaxonomyEntry` primary key; `taxonomy_name`, which takes four
    distinct values across the whole catalog and is determined by `taxonomy_slug`; and
    `reference_url`, which is derivable from `external_id` everywhere it is non-empty
    — 554 rows across four taxonomies, zero mismatches — and empty for all six `stride`
    entries. What remains costs 61% of the as-is payload.

    Two of the four URL templates look like one and are not. `mitre-attack` turns the
    sub-technique dot into a slash and `mitre-atlas` keeps it verbatim, so a caller
    reconstructing by pattern-match gets atlas wrong:

    ```text
    CAPEC-<n>  https://capec.mitre.org/data/definitions/<n>.html
    CWE-<n>    https://cwe.mitre.org/data/definitions/<n>.html
    <id>       https://attack.mitre.org/techniques/<id with "." -> "/">
    <id>       https://atlas.mitre.org/techniques/<id>
    ```
    """

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    # Not a `Literal`. The five seeded values are cwe, capec, mitre-attack,
    # mitre-atlas and stride, but taxonomies arrive from packs rather than from a
    # `choices` declaration, so a new pack adds a slug without a schema change.
    taxonomy_slug: str
    external_id: str
    title: str


class LibraryThreat(BaseModel):
    """One row of `GET /api/threat-library/`, projected."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    id: int
    name: str
    description: str

    # The pack name, not its id or slug. Which pack a threat came from is how a model
    # judges whether it applies to the system in front of it; the id is a primary key
    # no tool accepts. Nullable because `source_pack` is `null=True` for custom and
    # legacy items, not because the seeded catalog shows one — all 33 rows have a pack.
    source_pack_name: str | None = None

    taxonomy_entries: list[TaxonomyReference] = Field(default_factory=list)


class LibraryCountermeasure(BaseModel):
    """One row of `GET /api/countermeasure-library/`, projected.

    The list serializer carries `description` since the model-alignment work
    (plan section 7), so a query can match the mechanism a control's name does
    not mention. Defaulted because older fixtures and rows made by hand may
    leave it out.
    """

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    id: int
    name: str
    description: str = ""

    control_functions: list[str] = Field(default_factory=list)
    control_nature: str = ""

    cost: Literal["low", "medium", "high"]
    default_status: Literal["gap", "platform"]
    source_pack_name: str | None = None


class LibraryComponent(BaseModel):
    """One row of `GET /api/component-library/`, projected.

    This route has no list serializer — `ComponentLibraryViewSet` declares
    `serializer_class` outright — so the response carries `created_at` and
    `updated_at`. Both are dropped: these are shared templates imported from packs,
    and when one was written does not bear on whether it models the system at hand.
    """

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    id: int

    # `qualified_slug` rather than `slug`: the pack-namespaced form ("aws/lambda")
    # disambiguates the bare one ("lambda"), which is only unique within a pack.
    # Nullable in the schema; populated on all ten seeded rows.
    qualified_slug: str | None = None

    name: str
    category: Literal[
        "process", "datastore", "external_human_actor", "external_system_actor"
    ]

    # The CycloneDX asset type. `kind` is what the pack declared (blank when it
    # did not); `effective_kind` fills the blank from the category.
    kind: str = ""
    effective_kind: str = ""

    # Free text on both: `component_type` is a `CharField` with no choices, and
    # `provider` is `blank=True`, so an empty string means "not attributed to one".
    component_type: str
    provider: str = ""

    source_pack_name: str | None = None


class CatalogMatches(BaseModel):
    """The counts every catalog search returns beside its rows.

    Both are derivable from a complete response, which is what separates them from
    `ThreatModelListing.total` — the catalogs are unpaginated, so nothing is hidden.
    This type exists, so LLMs don't need to do math

    `catalog_size` is what makes "37 of 46" sayable, and that is the shape these answers
    want: how many matched means little without how many were searched.
    """

    # Aliased like the rows it wraps. Without this, one response would carry
    # `catalog_size` beside `sourcePackName`, and a client would have to know which
    # fields came from which side of this package.
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    matched: int = Field(
        description=(
            "How many entries matched. This is the length of `matches` — read it "
            "rather than counting them."
        ),
    )
    catalog_size: int = Field(
        description=(
            "How many entries the catalog holds in total, matching or not. Every one "
            "of them was searched, so `matched` of 0 means nothing matched rather than "
            "that the catalog was narrowed before searching."
        ),
    )


class LibraryThreatMatches(CatalogMatches):
    """What `search_threat_library` answers with."""

    matches: list[LibraryThreat]


class LibraryCountermeasureMatches(CatalogMatches):
    """What `search_countermeasure_library` answers with."""

    matches: list[LibraryCountermeasure]


class LibraryComponentMatches(CatalogMatches):
    """What `search_component_library` answers with."""

    matches: list[LibraryComponent]
