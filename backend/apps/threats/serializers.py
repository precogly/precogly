"""
Serializers for threats app.
"""

import re

from django.db import transaction
from rest_framework import serializers

from apps.core.scope import refuse_users_outside

from .models import (
    ComponentLibraryThreat,
    CountermeasureComment,
    CountermeasureLibrary,
    CountermeasureThreatLink,
    ExternalTaxonomy,
    InstanceCountermeasure,
    InstanceCountermeasureStandard,
    InstanceThreat,
    InstanceThreatTarget,
    InstanceThreatTaxonomyEntry,
    PentestFinding,
    Risk,
    RiskResponse,
    RiskThreat,
    TaxonomyEntry,
    ThreatLibrary,
    ThreatPersona,
    ThreatSource,
    VerificationTest,
)
from .services import (
    derive_risk_status,
    recalculate_residual,
)


class ExternalTaxonomySerializer(serializers.ModelSerializer):
    """Serializer for ExternalTaxonomy model."""

    entry_count = serializers.SerializerMethodField()

    class Meta:
        model = ExternalTaxonomy
        fields = [
            "id",
            "slug",
            "name",
            "description",
            "source_url",
            "version",
            "source_pack",
            "entry_count",
        ]
        read_only_fields = ["id"]

    def get_entry_count(self, obj):
        return obj.entries.count()


class TaxonomyEntryNestedSerializer(serializers.ModelSerializer):
    """Nested read-only serializer for taxonomy entries."""

    taxonomy_slug = serializers.CharField(source="taxonomy.slug", read_only=True)
    taxonomy_name = serializers.CharField(source="taxonomy.name", read_only=True)

    class Meta:
        model = TaxonomyEntry
        fields = [
            "id",
            "taxonomy_slug",
            "taxonomy_name",
            "external_id",
            "title",
            "reference_url",
        ]


def _build_taxonomy_entry_dict(entry, source):
    """Build a taxonomy entry dict with source provenance."""
    return {
        "id": entry.id,
        "taxonomy_slug": entry.taxonomy.slug,
        "taxonomy_name": entry.taxonomy.name,
        "external_id": entry.external_id,
        "title": entry.title,
        "reference_url": entry.reference_url,
        "source": source,
    }


def _merge_taxonomy_entries(threat_instance):
    """Merge library + instance taxonomy entries, fall back to snapshot.

    Returns a list of dicts with a 'source' field indicating provenance.
    Deduplicates by (taxonomy_slug, external_id); instance entries
    supplement library entries for the same key.
    """
    seen = {}

    if threat_instance.threat_library:
        for join in threat_instance.threat_library.taxonomy_entries.select_related(
            "taxonomy_entry__taxonomy"
        ).all():
            entry = join.taxonomy_entry
            key = (entry.taxonomy.slug, entry.external_id)
            seen[key] = _build_taxonomy_entry_dict(entry, "library")

    for link in threat_instance.instance_taxonomy_links.select_related(
        "taxonomy_entry__taxonomy"
    ).all():
        entry = link.taxonomy_entry
        key = (entry.taxonomy.slug, entry.external_id)
        if key not in seen:
            seen[key] = _build_taxonomy_entry_dict(entry, "instance")

    if not seen:
        for snap in threat_instance.taxonomy_snapshot:
            key = (snap.get("taxonomy_slug", ""), snap.get("external_id", ""))
            if key not in seen:
                seen[key] = {
                    "taxonomy_slug": snap.get("taxonomy_slug", ""),
                    "taxonomy_name": snap.get("taxonomy_name", ""),
                    "external_id": snap.get("external_id", ""),
                    "title": snap.get("title", ""),
                    "reference_url": snap.get("reference_url", ""),
                    "source": "snapshot",
                }

    return list(seen.values())


class ThreatLibrarySerializer(serializers.ModelSerializer):
    """Serializer for ThreatLibrary model."""

    source_pack_name = serializers.CharField(source="source_pack.name", read_only=True)
    source_pack_slug = serializers.CharField(source="source_pack.slug", read_only=True)
    taxonomy_entries = serializers.SerializerMethodField()

    class Meta:
        model = ThreatLibrary
        fields = [
            "id",
            "name",
            "description",
            "source_pack",
            "source_pack_name",
            "source_pack_slug",
            "taxonomy_entries",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "source_pack_name",
            "source_pack_slug",
            "taxonomy_entries",
        ]

    def get_taxonomy_entries(self, obj):
        joins = obj.taxonomy_entries.all()
        return TaxonomyEntryNestedSerializer(
            [j.taxonomy_entry for j in joins], many=True
        ).data


class ThreatLibraryListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for threat library listing."""

    source_pack_name = serializers.CharField(source="source_pack.name", read_only=True)
    source_pack_slug = serializers.CharField(source="source_pack.slug", read_only=True)
    taxonomy_entries = serializers.SerializerMethodField()

    class Meta:
        model = ThreatLibrary
        fields = [
            "id",
            "name",
            "description",
            "source_pack",
            "source_pack_name",
            "source_pack_slug",
            "taxonomy_entries",
        ]

    def get_taxonomy_entries(self, obj):
        joins = obj.taxonomy_entries.all()
        return TaxonomyEntryNestedSerializer(
            [j.taxonomy_entry for j in joins], many=True
        ).data


class CountermeasureLibrarySerializer(serializers.ModelSerializer):
    """Serializer for CountermeasureLibrary model."""

    source_pack_name = serializers.CharField(source="source_pack.name", read_only=True)
    source_pack_slug = serializers.CharField(source="source_pack.slug", read_only=True)

    class Meta:
        model = CountermeasureLibrary
        fields = [
            "id",
            "name",
            "description",
            "control_functions",
            "control_nature",
            "cost",
            "default_status",
            "source_pack",
            "source_pack_name",
            "source_pack_slug",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "source_pack_name",
            "source_pack_slug",
        ]


class CountermeasureLibraryListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for countermeasure library listing."""

    source_pack_name = serializers.CharField(source="source_pack.name", read_only=True)
    source_pack_slug = serializers.CharField(source="source_pack.slug", read_only=True)

    class Meta:
        model = CountermeasureLibrary
        fields = [
            "id",
            "name",
            "description",
            "control_functions",
            "control_nature",
            "cost",
            "default_status",
            "source_pack",
            "source_pack_name",
            "source_pack_slug",
        ]


class ComponentLibraryThreatSerializer(serializers.ModelSerializer):
    """Serializer for ComponentLibraryThreat associations."""

    threat_name = serializers.CharField(source="threat_library.name", read_only=True)
    component_name = serializers.CharField(
        source="component_library.name", read_only=True
    )

    class Meta:
        model = ComponentLibraryThreat
        fields = [
            "id",
            "component_library",
            "component_name",
            "threat_library",
            "threat_name",
            "default_level",
            "applies_to",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "threat_name",
            "component_name",
        ]


def rating_to_dict(rating) -> dict | None:
    """The read shape of a rating (#31 comment, 2.5)."""
    if rating is None:
        return None
    likelihood = None
    if rating.likelihood_level:
        likelihood = {
            "level": rating.likelihood_level,
            "score": rating.likelihood_score,
            "factors": rating.likelihood_factors or [],
            "extra": rating.likelihood_extra or {},
        }
    impact = None
    if rating.impact_level:
        impact = {
            "level": rating.impact_level,
            "score": rating.impact_score,
            "factors": rating.impact_factors or [],
            "extra": rating.impact_extra or {},
        }
    return {
        "id": rating.id,
        "methodology": rating.methodology,
        "level": rating.level,
        "score": rating.score,
        "likelihood": likelihood,
        "impact": impact,
        "rationale": rating.rationale,
    }


class RatingField(serializers.Field):
    """Read-only nested rating."""

    def __init__(self, **kwargs):
        kwargs["read_only"] = True
        super().__init__(**kwargs)

    def to_representation(self, rating):
        return rating_to_dict(rating)


RISK_DOMAINS = (
    "security",
    "privacy",
    "operational",
    "financial",
    "compliance",
    "strategic",
    "reputational",
    "safety",
    "environmental",
    "supply-chain",
    "technical",
    "project",
    "ethical",
    "societal",
    "human-rights",
    "health",
    "legal",
)

IMPACT_CATEGORIES = (
    "confidentiality",
    "integrity",
    "availability",
    "financial",
    "reputation",
    "regulatory",
    "safety",
    "privacy",
    "operational",
    "strategic",
    "bias",
    "discrimination",
    "fairness",
    "human-rights",
    "environmental",
    "societal",
    "psychological",
    "physical",
    "health",
)


def validate_impact_extra(inputs: dict) -> dict:
    """The form's impact section: categories and quantification (section 4.2).

    Returns the ``impact_extra`` dict to store; raises on bad values since no
    engine writes these.
    """
    extra = {}
    categories = inputs.get("impact_categories")
    if categories is not None:
        if not isinstance(categories, list) or any(
            c not in IMPACT_CATEGORIES for c in categories
        ):
            raise serializers.ValidationError(
                {
                    "rating_inputs": "impact_categories must be a list of impact category values."
                }
            )
        if categories:
            extra["categories"] = list(dict.fromkeys(categories))
    quantification = inputs.get("impact_quantification")
    if quantification is not None:
        if not isinstance(quantification, dict):
            raise serializers.ValidationError(
                {"rating_inputs": "impact_quantification must be an object."}
            )
        cleaned = {}
        loss = quantification.get("financial_loss", quantification.get("financialLoss"))
        if loss is not None:
            if not isinstance(loss, (int, float)) or isinstance(loss, bool) or loss < 0:
                raise serializers.ValidationError(
                    {"rating_inputs": "financial_loss must be a non-negative number."}
                )
            cleaned["financialLoss"] = loss
        currency = quantification.get("currency")
        if currency is not None:
            if not isinstance(currency, str) or not re.fullmatch(r"[A-Z]{3}", currency):
                raise serializers.ValidationError(
                    {"rating_inputs": "currency must be an ISO 4217 code such as USD."}
                )
            cleaned["currency"] = currency
        loss_range = quantification.get(
            "financial_loss_range", quantification.get("financialLossRange")
        )
        if loss_range is not None:
            if not isinstance(loss_range, dict):
                raise serializers.ValidationError(
                    {"rating_inputs": "financial_loss_range must be an object."}
                )
            cleaned_range = {}
            for ours, theirs in (
                ("minimum", "minimum"),
                ("most_likely", "mostLikely"),
                ("maximum", "maximum"),
            ):
                value = loss_range.get(ours, loss_range.get(theirs))
                if value is None:
                    continue
                if not isinstance(value, (int, float)) or isinstance(value, bool):
                    raise serializers.ValidationError(
                        {
                            "rating_inputs": f"financial_loss_range.{ours} must be a number."
                        }
                    )
                cleaned_range[theirs] = value
            if cleaned_range:
                cleaned["financialLossRange"] = cleaned_range
        if cleaned:
            extra["quantification"] = cleaned
    return extra


def rating_from_inputs(threat_model, inputs, *, for_threat: bool):
    """Validate and rate ``rating_inputs``, with the impact section applied."""
    from .services import rate_inputs

    if not isinstance(inputs, dict):
        raise serializers.ValidationError({"rating_inputs": "Must be an object."})
    engine_inputs = {
        key: value
        for key, value in inputs.items()
        if key not in ("impact_categories", "impact_quantification")
    }
    rating = rate_inputs(threat_model, engine_inputs, for_threat=for_threat)
    extra = validate_impact_extra(inputs)
    if extra:
        rating.impact_extra = {**(rating.impact_extra or {}), **extra}
    return rating


class BusinessObjectiveIdsField(serializers.ListField):
    """Ids of a model's business objectives; resolved against the owner's model."""

    child = serializers.IntegerField()


def resolve_business_objectives(threat_model, ids):
    from apps.threat_models.models import BusinessObjective

    wanted = list(dict.fromkeys(ids))
    found = {
        objective.id: objective
        for objective in BusinessObjective.objects.filter(
            id__in=wanted, threat_model=threat_model
        )
    }
    missing = [i for i in wanted if i not in found]
    if missing:
        raise serializers.ValidationError(
            {
                "business_objective_ids": f"business objective(s) {missing} are not "
                "part of this threat model."
            }
        )
    return [found[i] for i in wanted]


def objective_names(links):
    return [
        {"id": link.business_objective_id, "name": link.business_objective.name}
        for link in links
    ]


class ThreatTargetsField(serializers.Field):
    """The ``targets`` list of a scenario.

    Reads as ``[{type, id, name, blueprint_id}]``; writes take ``[{type, id}]``
    and are resolved against the scenario's threat model in ``validate``.
    """

    default_error_messages = {
        "not_a_list": "targets must be a list of {type, id} objects.",
        "bad_entry": "Each target needs a type (component, flow, zone, boundary) and an id.",
    }

    def to_representation(self, threat):
        from apps.threat_models.analysis_service import serialize_targets

        return serialize_targets(threat)

    def to_internal_value(self, data):
        if not isinstance(data, list):
            self.fail("not_a_list")
        entries = []
        for item in data:
            if not isinstance(item, dict):
                self.fail("bad_entry")
            kind = item.get("type")
            target_id = item.get("id")
            if kind not in InstanceThreatTarget.TARGET_KINDS or target_id is None:
                self.fail("bad_entry")
            entries.append({"type": kind, "id": target_id})
        return entries

    def get_attribute(self, instance):
        return instance


class InstanceThreatSerializer(serializers.ModelSerializer):
    """One scenario: its targets, number, triage and actor.

    Writes take ``targets`` as ``[{type, id}]`` plus ``whole_system``. A
    scenario either has targets or is whole-system, never both and never
    neither; the actor is a persona of the model or free text, never both.
    """

    threat_name_display = serializers.SerializerMethodField()
    taxonomy_entries = serializers.SerializerMethodField()
    threat_sources = serializers.SerializerMethodField()
    display_number = serializers.CharField(read_only=True)
    targets = ThreatTargetsField(required=False)
    rating = RatingField()
    rating_inputs = serializers.JSONField(write_only=True, required=False)
    business_objective_ids = BusinessObjectiveIdsField(required=False)
    business_objectives = serializers.SerializerMethodField()
    threat_source_ids = serializers.ListField(
        child=serializers.IntegerField(), write_only=True, required=False
    )
    actor_persona_name = serializers.CharField(
        source="actor_persona.name", read_only=True, default=None
    )

    def get_business_objectives(self, obj):
        return objective_names(obj.business_objective_links.all())

    # Write fields - accept threat_name/threat_description for custom threats
    threat_name = serializers.CharField(
        required=False, allow_blank=True, write_only=True
    )
    threat_description = serializers.CharField(
        required=False, allow_blank=True, write_only=True
    )

    class Meta:
        model = InstanceThreat
        fields = [
            "id",
            "threat_model",
            "number",
            "display_number",
            "whole_system",
            "targets",
            "auto_generated",
            "threat_library",
            "threat_name",
            "threat_description",
            "threat_name_display",
            "taxonomy_entries",
            "rating",
            "rating_inputs",
            "business_objective_ids",
            "threat_source_ids",
            "business_objectives",
            "status",
            "triage_status",
            "decision_rationale",
            "format_metadata",
            "display_order",
            "impact_description",
            "actor_persona",
            "actor_persona_name",
            "threat_actor_text",
            "intent",
            "access_level",
            "threat_sources",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "format_metadata",
            "id",
            "number",
            "display_number",
            "auto_generated",
            "rating",
            "business_objectives",
            "created_at",
            "updated_at",
            "threat_name_display",
            "taxonomy_entries",
            "threat_sources",
            "actor_persona_name",
        ]

    def get_threat_name_display(self, obj):
        """Return threat name from model field or threat_library."""
        if obj.threat_name:
            return obj.threat_name
        if obj.threat_library:
            return obj.threat_library.name
        return None

    def get_taxonomy_entries(self, obj):
        """Merge library + instance taxonomy entries, fall back to snapshot."""
        return _merge_taxonomy_entries(obj)

    def validate_threat_source_ids(self, value):
        """Shared reference rows (``Tenancy.SHARED_REFERENCE``): existence is
        the whole check, no organization scope applies."""
        wanted = list(dict.fromkeys(value))
        found = {
            source.pk: source for source in ThreatSource.objects.filter(pk__in=wanted)
        }
        if len(found) != len(wanted):
            raise serializers.ValidationError("Unknown threat source.")
        return [found[source_id] for source_id in wanted]

    def get_threat_sources(self, obj):
        return [
            {"id": link.source.id, "name": link.source.name, "slug": link.source.slug}
            for link in obj.source_links.select_related("source").all()
        ]

    def validate(self, attrs):
        from .services import resolve_target

        threat_model = attrs.get("threat_model") or getattr(
            self.instance, "threat_model", None
        )
        if threat_model is None:
            raise serializers.ValidationError(
                {"threat_model": "This field is required."}
            )
        if (
            self.instance is not None
            and "threat_model" in attrs
            and attrs["threat_model"] != self.instance.threat_model
        ):
            raise serializers.ValidationError(
                {"threat_model": "A scenario cannot move to another threat model."}
            )

        if "targets" in attrs or "whole_system" in attrs or self.instance is None:
            whole_system = attrs.get(
                "whole_system", getattr(self.instance, "whole_system", False)
            )
            if "targets" in attrs:
                rows = []
                for entry in attrs["targets"]:
                    row = resolve_target(entry["type"], entry["id"], threat_model)
                    if row is None:
                        raise serializers.ValidationError(
                            {
                                "targets": f"{entry['type']} {entry['id']} is not part "
                                "of this threat model."
                            }
                        )
                    rows.append(row)
                attrs["targets"] = rows
            elif self.instance is None:
                attrs["targets"] = []
            target_rows = attrs.get("targets")
            if target_rows is None and self.instance is not None:
                # Only the flag was sent: check it against the stored targets.
                target_rows = list(self.instance.targets.all())
                if whole_system:
                    target_rows = []
            if target_rows is not None:
                if target_rows and whole_system:
                    raise serializers.ValidationError(
                        {"targets": "A whole-system scenario has no targets."}
                    )
                if not target_rows and not whole_system:
                    raise serializers.ValidationError(
                        {
                            "targets": "Give at least one target, or set whole_system "
                            "to make this a whole-system scenario."
                        }
                    )

        if "business_objective_ids" in attrs:
            attrs["business_objective_ids"] = resolve_business_objectives(
                threat_model, attrs["business_objective_ids"]
            )

        persona = attrs.get(
            "actor_persona", getattr(self.instance, "actor_persona", None)
        )
        actor_text = attrs.get(
            "threat_actor_text", getattr(self.instance, "threat_actor_text", "")
        )
        if persona is not None and actor_text:
            raise serializers.ValidationError(
                {"threat_actor_text": "Choose a persona or type an actor, not both."}
            )
        if persona is not None and persona.threat_model_id != threat_model.id:
            raise serializers.ValidationError(
                {"actor_persona": "The persona must belong to this threat model."}
            )
        return attrs

    @transaction.atomic
    def create(self, validated_data):
        from .services import create_instance_threat

        targets = validated_data.pop("targets", [])
        whole_system = validated_data.pop("whole_system", False)
        threat_model = validated_data.pop("threat_model")
        rating_inputs = validated_data.pop("rating_inputs", None)
        objectives = validated_data.pop("business_objective_ids", [])
        sources = validated_data.pop("threat_source_ids", [])
        rating = (
            rating_from_inputs(threat_model, rating_inputs, for_threat=True)
            if rating_inputs
            else None
        )
        threat = create_instance_threat(
            threat_model,
            targets=targets,
            whole_system=whole_system,
            rating=rating,
            **validated_data,
        )
        if objectives:
            from .services import set_threat_business_objectives

            set_threat_business_objectives(threat, objectives)
        if sources:
            from .services import set_threat_sources

            set_threat_sources(threat, sources)
        return threat

    @transaction.atomic
    def update(self, instance, validated_data):
        from .services import (
            apply_rating,
            note_user_edit,
            recalculate_risks_for_threat,
            set_targets,
            set_threat_business_objectives,
            set_threat_sources,
        )

        targets = validated_data.pop("targets", None)
        whole_system = validated_data.pop("whole_system", None)
        rating_inputs = validated_data.pop("rating_inputs", None)
        objectives = validated_data.pop("business_objective_ids", None)
        sources = validated_data.pop("threat_source_ids", None)
        validated_data.pop("threat_model", None)
        instance = super().update(instance, validated_data)
        if objectives is not None:
            set_threat_business_objectives(instance, objectives)
        if sources is not None:
            # [] clears them all; note_user_edit below marks the threat edited.
            set_threat_sources(instance, sources)
        if rating_inputs:
            apply_rating(
                instance,
                "rating",
                rating_from_inputs(
                    instance.threat_model, rating_inputs, for_threat=True
                ),
            )
            recalculate_risks_for_threat(instance)
        if targets is not None or whole_system is not None:
            if whole_system is None:
                whole_system = False if targets else instance.whole_system
            if targets is None:
                targets = (
                    []
                    if whole_system
                    else [row.target for row in instance.targets.all()]
                )
            set_targets(instance, targets, whole_system=whole_system)
            # The viewset prefetched the old target rows; read the new ones.
            instance.refresh_from_db()
        note_user_edit(instance)
        return instance


class CountermeasureThreatLinkSerializer(serializers.ModelSerializer):
    """Read-only serializer for linked scenarios on a countermeasure."""

    threat_id = serializers.IntegerField(read_only=True)
    display_number = serializers.CharField(
        source="threat.display_number", read_only=True
    )
    threat_name = serializers.SerializerMethodField()
    targets = serializers.SerializerMethodField()

    class Meta:
        model = CountermeasureThreatLink
        fields = [
            "id",
            "threat_id",
            "display_number",
            "threat_name",
            "targets",
            "display_order",
        ]
        read_only_fields = fields

    def get_threat_name(self, obj):
        threat = obj.threat
        return threat.threat_name or (
            threat.threat_library.name if threat.threat_library else None
        )

    def get_targets(self, obj):
        from apps.threat_models.analysis_service import serialize_targets

        return serialize_targets(obj.threat)


class CountermeasureTargetsField(ThreatTargetsField):
    """``targets`` of a control: where it applies. Empty means the whole system."""

    def to_representation(self, countermeasure):
        from apps.threat_models.analysis_service import serialize_targets

        return serialize_targets(countermeasure)


class InstanceCountermeasureSerializer(serializers.ModelSerializer):
    """Serializer for InstanceCountermeasure.

    ``targets`` (``[{type, id}]`` on write) say where the control applies and
    never change a threat's status; ``implemented_by`` lists the components
    that implement it; ``implemented_by_party`` names a provider as text.
    """

    # Read fields - prefer model's own fields, fallback to countermeasure_library
    countermeasure_name_display = serializers.SerializerMethodField()
    control_functions_display = serializers.SerializerMethodField()
    control_nature_display = serializers.SerializerMethodField()
    display_number = serializers.CharField(read_only=True)
    days_overdue = serializers.ReadOnlyField()
    targets = CountermeasureTargetsField(required=False)
    implemented_by = serializers.ListField(
        child=serializers.IntegerField(), required=False
    )
    verified_by_email = serializers.EmailField(
        source="verified_by.email", read_only=True
    )
    assigned_owner_email = serializers.EmailField(
        source="assigned_owner.email", read_only=True
    )
    threat_links = CountermeasureThreatLinkSerializer(many=True, read_only=True)

    # Write fields - accept custom countermeasure data
    countermeasure_name = serializers.CharField(
        required=False, allow_blank=True, write_only=True
    )
    countermeasure_description = serializers.CharField(
        required=False, allow_blank=True, write_only=True
    )
    control_functions = serializers.ListField(
        child=serializers.CharField(), required=False, write_only=True
    )
    control_nature = serializers.CharField(
        required=False, allow_blank=True, write_only=True
    )
    threat_id = serializers.IntegerField(write_only=True, required=False)

    class Meta:
        model = InstanceCountermeasure
        fields = [
            "id",
            "threat_model",
            "countermeasure_library",
            "countermeasure_name",
            "countermeasure_name_display",
            "countermeasure_description",
            "control_functions",
            "control_functions_display",
            "control_nature",
            "control_nature_display",
            "effectiveness",
            "status",
            "priority",
            "due_date",
            "external_ticket_url",
            "verified_by",
            "verified_by_email",
            "evidence_url",
            "required_for_release",
            "assigned_owner",
            "assigned_owner_email",
            "format_metadata",
            "threat_links",
            "threat_id",
            "auto_generated",
            "number",
            "display_number",
            "days_overdue",
            "targets",
            "implemented_by",
            "implemented_by_party",
            "source",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "format_metadata",
            "id",
            "created_at",
            "updated_at",
            "countermeasure_name_display",
            "control_functions_display",
            "control_nature_display",
            "verified_by_email",
            "assigned_owner_email",
            "threat_links",
            "auto_generated",
            "number",
            "display_number",
            "days_overdue",
        ]

    def get_countermeasure_name_display(self, obj):
        """Return countermeasure name from model field or countermeasure_library."""
        if obj.countermeasure_name:
            return obj.countermeasure_name
        if obj.countermeasure_library:
            return obj.countermeasure_library.name
        return None

    def get_control_functions_display(self, obj):
        """Return control functions from model field or countermeasure_library."""
        if obj.control_functions:
            return obj.control_functions
        if obj.countermeasure_library:
            return obj.countermeasure_library.control_functions
        return []

    def get_control_nature_display(self, obj):
        """Return control nature from model field or countermeasure_library."""
        if obj.control_nature:
            return obj.control_nature
        if obj.countermeasure_library:
            return obj.countermeasure_library.control_nature
        return ""

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["implemented_by"] = [
            link.component_id for link in instance.provider_links.all()
        ]
        return data

    def validate(self, attrs):
        from apps.systems.models import OrgsystemComponent

        from .services import resolve_target

        threat_id = attrs.get("threat_id")
        threat_model = attrs.get("threat_model") or getattr(
            self.instance, "threat_model", None
        )
        if threat_model is None:
            raise serializers.ValidationError(
                {"threat_model": "This field is required."}
            )
        if (
            self.instance is not None
            and "threat_model" in attrs
            and attrs["threat_model"] != self.instance.threat_model
        ):
            raise serializers.ValidationError(
                {
                    "threat_model": "A countermeasure cannot move to another threat model."
                }
            )
        refuse_users_outside(
            attrs, threat_model.organization_id, "assigned_owner", "verified_by"
        )
        if (
            threat_id is not None
            and not InstanceThreat.objects.filter(
                id=threat_id, threat_model=threat_model
            ).exists()
        ):
            raise serializers.ValidationError(
                {"threat_id": "The threat is not part of this threat model."}
            )
        if "targets" in attrs:
            rows = []
            for entry in attrs["targets"]:
                row = resolve_target(entry["type"], entry["id"], threat_model)
                if row is None:
                    raise serializers.ValidationError(
                        {
                            "targets": f"{entry['type']} {entry['id']} is not part "
                            "of this threat model."
                        }
                    )
                rows.append(row)
            attrs["targets"] = rows
        if "implemented_by" in attrs:
            wanted = list(dict.fromkeys(attrs["implemented_by"]))
            components = {
                component.id: component
                for component in OrgsystemComponent.objects.filter(
                    id__in=wanted, blueprint__threat_model=threat_model
                )
            }
            missing = [
                component_id
                for component_id in wanted
                if component_id not in components
            ]
            if missing:
                raise serializers.ValidationError(
                    {
                        "implemented_by": f"component(s) {missing} are not part of "
                        "this threat model."
                    }
                )
            attrs["implemented_by"] = [
                components[component_id] for component_id in wanted
            ]
        return attrs

    @transaction.atomic
    def create(self, validated_data):
        from .services import create_instance_countermeasure, link_countermeasure

        threat_id = validated_data.pop("threat_id", None)
        threat_model = validated_data.pop("threat_model")
        instance = create_instance_countermeasure(
            threat_model,
            user=getattr(self.context.get("request"), "user", None),
            **validated_data,
        )
        if threat_id:
            link_countermeasure(instance, InstanceThreat.objects.get(id=threat_id))
        return instance

    @transaction.atomic
    def update(self, instance, validated_data):
        from .services import set_countermeasure_providers, set_countermeasure_targets

        targets = validated_data.pop("targets", None)
        implemented_by = validated_data.pop("implemented_by", None)
        validated_data.pop("threat_id", None)
        validated_data.pop("threat_model", None)
        instance = super().update(instance, validated_data)
        if targets is not None:
            set_countermeasure_targets(instance, targets)
        if implemented_by is not None:
            set_countermeasure_providers(instance, implemented_by)
        if targets is not None or implemented_by is not None:
            instance.refresh_from_db()
        return instance


class VerificationTestSerializer(serializers.ModelSerializer):
    """Serializer for VerificationTest."""

    class Meta:
        model = VerificationTest
        fields = [
            "id",
            "name",
            "method",
            "last_run_at",
            "passed",
            "evidence",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class PentestFindingSerializer(serializers.ModelSerializer):
    """Serializer for PentestFinding."""

    matched_threat_name = serializers.CharField(
        source="matched_threat_library.name", read_only=True
    )

    class Meta:
        model = PentestFinding
        fields = [
            "id",
            "threat_model",
            "finding_description",
            "severity",
            "matched_threat_library",
            "matched_threat_name",
            "matched_countermeasure",
            "reconciliation_status",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at", "matched_threat_name"]

    def validate(self, attrs):
        threat_model = attrs.get("threat_model") or getattr(
            self.instance, "threat_model", None
        )
        countermeasure = attrs.get(
            "matched_countermeasure",
            getattr(self.instance, "matched_countermeasure", None),
        )
        if (
            countermeasure is not None
            and threat_model is not None
            and countermeasure.threat_model_id != threat_model.id
        ):
            raise serializers.ValidationError(
                {
                    "matched_countermeasure": "The countermeasure must belong to "
                    "this threat model."
                }
            )
        return attrs


class InstanceCountermeasureStandardSerializer(serializers.ModelSerializer):
    """Serializer for InstanceCountermeasureStandard (instance-level compliance mappings)."""

    framework_name = serializers.SerializerMethodField()
    framework_slug = serializers.SerializerMethodField()
    section_code = serializers.SerializerMethodField()
    requirement_description = serializers.SerializerMethodField()

    class Meta:
        model = InstanceCountermeasureStandard
        fields = [
            "id",
            "countermeasure",
            "requirement",
            "framework_name",
            "framework_slug",
            "section_code",
            "requirement_description",
            "sufficiency",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "framework_name",
            "framework_slug",
            "section_code",
            "requirement_description",
        ]

    def validate(self, attrs):
        """A model's own framework is usable only inside that model's organization."""
        countermeasure = attrs.get(
            "countermeasure", getattr(self.instance, "countermeasure", None)
        )
        requirement = attrs.get("requirement")
        framework = getattr(requirement, "framework", None)
        if (
            countermeasure is not None
            and framework is not None
            and framework.threat_model_id is not None
            and framework.threat_model.organization_id
            != countermeasure.threat_model.organization_id
        ):
            raise serializers.ValidationError(
                {"requirement": "The requirement is not available to this model."}
            )
        return attrs

    def get_framework_name(self, obj):
        if obj.requirement and obj.requirement.framework:
            return obj.requirement.framework.name
        return obj.framework_name

    def get_framework_slug(self, obj):
        if obj.requirement and obj.requirement.framework:
            return obj.requirement.framework.slug
        return ""

    def get_section_code(self, obj):
        if obj.requirement:
            return obj.requirement.section_code
        return obj.section_code

    def get_requirement_description(self, obj):
        if obj.requirement:
            return obj.requirement.description
        return obj.requirement_description

    def create(self, validated_data):
        requirement = validated_data.get("requirement")
        if requirement:
            validated_data["section_code"] = requirement.section_code
            validated_data["framework_name"] = requirement.framework.name
            validated_data["requirement_description"] = requirement.description
        return super().create(validated_data)


class InstanceThreatTaxonomyEntrySerializer(serializers.ModelSerializer):
    """Serializer for instance-level taxonomy entries on threat scenarios."""

    taxonomy_slug = serializers.CharField(
        source="taxonomy_entry.taxonomy.slug", read_only=True
    )
    taxonomy_name = serializers.CharField(
        source="taxonomy_entry.taxonomy.name", read_only=True
    )
    external_id = serializers.CharField(
        source="taxonomy_entry.external_id", read_only=True
    )
    title = serializers.CharField(source="taxonomy_entry.title", read_only=True)
    reference_url = serializers.URLField(
        source="taxonomy_entry.reference_url", read_only=True
    )

    class Meta:
        model = InstanceThreatTaxonomyEntry
        fields = [
            "id",
            "taxonomy_entry",
            "threat",
            "taxonomy_slug",
            "taxonomy_name",
            "external_id",
            "title",
            "reference_url",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "taxonomy_slug",
            "taxonomy_name",
            "external_id",
            "title",
            "reference_url",
        ]

    def create(self, validated_data):
        from django.db import IntegrityError

        from .services import note_user_edit

        try:
            entry = super().create(validated_data)
        except IntegrityError as err:
            raise serializers.ValidationError(
                "This taxonomy entry is already linked to this threat."
            ) from err
        note_user_edit(entry.threat)
        return entry


class CountermeasureCommentSerializer(serializers.ModelSerializer):
    """Serializer for CountermeasureComment."""

    author_email = serializers.EmailField(
        source="author.email", read_only=True, default=None
    )

    class Meta:
        model = CountermeasureComment
        fields = [
            "id",
            "author",
            "author_email",
            "countermeasure",
            "body",
            "change_summary",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "author", "author_email", "created_at", "updated_at"]

    def create(self, validated_data):
        validated_data["author"] = self.context["request"].user
        return super().create(validated_data)


class RiskListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for risk listing."""

    scoring_method = serializers.SerializerMethodField()
    threat_count = serializers.SerializerMethodField()
    inherent = RatingField()
    residual = RatingField()
    target = RatingField()
    exposure = serializers.SerializerMethodField()
    owner_email = serializers.EmailField(
        source="owner.email", read_only=True, default=None
    )
    assigned_to_email = serializers.EmailField(
        source="assigned_to.email", read_only=True, default=None
    )

    def get_exposure(self, obj):
        return derive_risk_status(obj)

    class Meta:
        model = Risk
        fields = [
            "id",
            "name",
            "description",
            "scoring_method",
            "inherent",
            "residual",
            "target",
            "status",
            "exposure",
            "threat_count",
            "owner",
            "owner_email",
            "assigned_to",
            "assigned_to_email",
            "created_at",
            "updated_at",
        ]

    def get_scoring_method(self, obj):
        return obj.threat_model.risk_scoring_method

    def get_threat_count(self, obj):
        annotated = getattr(obj, "threat_count", None)
        if annotated is not None:
            return annotated
        return obj.risk_threats.count()


class RiskDetailSerializer(serializers.ModelSerializer):
    """Full serializer for risk detail/create/update.

    Writes take ``rating_inputs`` (a level alone, or the model's method's
    inputs) for the inherent rating; residual is always computed.
    """

    scoring_method = serializers.SerializerMethodField()
    inherent = RatingField()
    residual = RatingField()
    target = RatingField()
    rating_inputs = serializers.JSONField(write_only=True, required=False)
    exposure = serializers.SerializerMethodField()
    responses = serializers.SerializerMethodField()
    business_objective_ids = BusinessObjectiveIdsField(required=False)
    business_objectives = serializers.SerializerMethodField()

    def get_business_objectives(self, obj):
        return objective_names(obj.business_objective_links.all())

    owner_email = serializers.EmailField(
        source="owner.email", read_only=True, default=None
    )
    assigned_to_email = serializers.EmailField(
        source="assigned_to.email", read_only=True, default=None
    )
    threats = serializers.SerializerMethodField()

    def get_exposure(self, obj):
        return derive_risk_status(obj)

    def get_responses(self, obj):
        return RiskResponseSerializer(obj.responses.all(), many=True).data

    # Write-only field for inline threat linking
    threat_ids = serializers.ListField(
        child=serializers.IntegerField(), write_only=True, required=False, default=[]
    )

    class Meta:
        model = Risk
        fields = [
            "id",
            "name",
            "description",
            "scoring_method",
            "inherent",
            "residual",
            "target",
            "rating_inputs",
            "status",
            "statement",
            "exposure",
            "domains",
            "business_objective_ids",
            "business_objectives",
            "responses",
            "threats",
            "owner",
            "owner_email",
            "assigned_to",
            "assigned_to_email",
            "format_metadata",
            "threat_ids",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "format_metadata",
            "id",
            "inherent",
            "residual",
            "target",
            "exposure",
            "responses",
            "business_objectives",
            "created_at",
            "updated_at",
        ]

    def validate_domains(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("domains must be a list.")
        cleaned = []
        for item in value:
            name = item.get("type") if isinstance(item, dict) else item
            if name not in RISK_DOMAINS:
                raise serializers.ValidationError(
                    f"'{name}' is not a risk domain. Use one of: "
                    + ", ".join(RISK_DOMAINS)
                )
            if name not in cleaned:
                cleaned.append(name)
        return cleaned

    def _threat_model(self):
        threat_model = self.context.get("threat_model")
        if threat_model is None and self.instance is not None:
            threat_model = self.instance.threat_model
        return threat_model

    def get_scoring_method(self, obj):
        return obj.threat_model.risk_scoring_method

    def get_threats(self, obj):
        """Return linked scenarios with basic info."""
        from apps.threat_models.analysis_service import serialize_targets

        result = []
        for risk_threat in (
            obj.risk_threats.select_related(
                "threat", "threat__threat_library", "threat__rating"
            )
            .prefetch_related("threat__targets")
            .all()
        ):
            threat = risk_threat.threat
            result.append(
                {
                    "risk_threat_id": risk_threat.id,
                    "threat_id": threat.id,
                    "display_number": threat.display_number,
                    "threat_name": threat.threat_name
                    or (threat.threat_library.name if threat.threat_library else None),
                    "status": threat.status,
                    "triage_status": threat.triage_status,
                    "whole_system": threat.whole_system,
                    "rating": rating_to_dict(threat.rating),
                    "targets": serialize_targets(threat),
                }
            )
        return result

    def validate(self, attrs):
        """Every threat id belongs to the same model; rating inputs rate now."""
        threat_model = self._threat_model()
        refuse_users_outside(
            attrs,
            getattr(threat_model, "organization_id", None),
            "owner",
            "assigned_to",
        )
        threat_ids = attrs.get("threat_ids", [])
        if threat_model and threat_ids:
            valid_count = InstanceThreat.objects.filter(
                id__in=threat_ids, threat_model=threat_model
            ).count()
            if valid_count != len(set(threat_ids)):
                raise serializers.ValidationError(
                    {
                        "threat_ids": "One or more threats are not part of this threat model."
                    }
                )
        if "business_objective_ids" in attrs:
            attrs["business_objective_ids"] = resolve_business_objectives(
                threat_model, attrs["business_objective_ids"]
            )
        if "rating_inputs" in attrs:
            if threat_model is None:
                raise serializers.ValidationError({"rating_inputs": "No threat model."})
            attrs["_rating"] = rating_from_inputs(
                threat_model, attrs.pop("rating_inputs"), for_threat=False
            )
        elif self.instance is None:
            raise serializers.ValidationError(
                {
                    "rating_inputs": "Give a level, or the method's inputs, to rate the risk."
                }
            )
        return attrs

    def create(self, validated_data):
        from .services import create_risk, set_risk_business_objectives

        threat_ids = validated_data.pop("threat_ids", [])
        rating = validated_data.pop("_rating")
        objectives = validated_data.pop("business_objective_ids", [])
        threat_model = validated_data.pop("threat_model", None) or self._threat_model()
        risk = create_risk(
            threat_model, rating=rating, threat_ids=threat_ids, **validated_data
        )
        if objectives:
            set_risk_business_objectives(risk, objectives)
        return risk

    def update(self, instance, validated_data):
        from .services import apply_rating, set_risk_business_objectives

        validated_data.pop("threat_ids", None)
        rating = validated_data.pop("_rating", None)
        objectives = validated_data.pop("business_objective_ids", None)
        instance = super().update(instance, validated_data)
        if objectives is not None:
            set_risk_business_objectives(instance, objectives)
        if rating is not None:
            apply_rating(instance, "inherent", rating)
        recalculate_residual(instance)
        instance.refresh_from_db()
        return instance


class RiskResponseSerializer(serializers.ModelSerializer):
    """A risk's response: strategy, status, cost, priority, owner, target date
    and the controls it relies on (``countermeasure_ids``, same model only)."""

    owner_email = serializers.EmailField(
        source="owner.email", read_only=True, default=None
    )
    countermeasure_ids = serializers.ListField(
        child=serializers.IntegerField(), required=False
    )
    countermeasures = serializers.SerializerMethodField()

    class Meta:
        model = RiskResponse
        fields = [
            "id",
            "risk",
            "strategy",
            "description",
            "status",
            "effectiveness",
            "cost",
            "priority",
            "owner",
            "owner_email",
            "target_date",
            "countermeasure_ids",
            "countermeasures",
            "format_metadata",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "risk",
            "owner_email",
            "countermeasures",
            "format_metadata",
            "created_at",
            "updated_at",
        ]

    def get_countermeasures(self, obj):
        return [
            {
                "id": link.countermeasure_id,
                "display_number": link.countermeasure.display_number,
                "countermeasure_name": link.countermeasure.countermeasure_name,
                "status": link.countermeasure.status,
            }
            for link in obj.countermeasure_links.all()
        ]

    def validate(self, attrs):
        risk = self.context.get("risk") or getattr(self.instance, "risk", None)
        organization_id = risk.threat_model.organization_id if risk else None
        refuse_users_outside(attrs, organization_id, "owner")
        return attrs

    def validate_countermeasure_ids(self, value):
        risk = self.context.get("risk") or getattr(self.instance, "risk", None)
        if risk is None:
            raise serializers.ValidationError("No risk.")
        wanted = list(dict.fromkeys(value))
        found = {
            countermeasure.id: countermeasure
            for countermeasure in InstanceCountermeasure.objects.filter(
                id__in=wanted, threat_model=risk.threat_model
            )
        }
        missing = [i for i in wanted if i not in found]
        if missing:
            raise serializers.ValidationError(
                f"countermeasure(s) {missing} are not part of this threat model."
            )
        return [found[i] for i in wanted]

    def create(self, validated_data):
        from .services import create_risk_response

        countermeasures = validated_data.pop("countermeasure_ids", [])
        risk = validated_data.pop("risk", None) or self.context.get("risk")
        return create_risk_response(
            risk, countermeasures=countermeasures, **validated_data
        )

    def update(self, instance, validated_data):
        from .services import set_response_countermeasures

        countermeasures = validated_data.pop("countermeasure_ids", None)
        validated_data.pop("risk", None)
        instance = super().update(instance, validated_data)
        if countermeasures is not None:
            set_response_countermeasures(instance, countermeasures)
            instance.refresh_from_db()
        return instance


class RiskThreatSerializer(serializers.ModelSerializer):
    """Serializer for RiskThreat junction rows."""

    threat_name = serializers.SerializerMethodField()
    display_number = serializers.CharField(
        source="threat.display_number", read_only=True
    )

    class Meta:
        model = RiskThreat
        fields = ["id", "risk", "threat", "display_number", "threat_name", "created_at"]
        read_only_fields = ["id", "display_number", "threat_name", "created_at"]

    def get_threat_name(self, obj):
        threat = obj.threat
        return threat.threat_name or (
            threat.threat_library.name if threat.threat_library else None
        )


class ThreatPersonaSerializer(serializers.ModelSerializer):
    """Serializer for ThreatPersona CRUD. The threat model comes from the URL;
    ``threat_count`` is the number of threats citing the persona (plan J10)."""

    threat_count = serializers.SerializerMethodField()

    class Meta:
        model = ThreatPersona
        fields = [
            "id",
            "threat_model",
            "symbolic_name",
            "name",
            "description",
            "is_person",
            "malicious_intent",
            "skill_level",
            "motivation",
            "resources",
            "objectives",
            "format_metadata",
            "threat_count",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "format_metadata",
            "id",
            "threat_model",
            "threat_count",
            "created_at",
            "updated_at",
        ]

    def get_threat_count(self, obj):
        annotated = getattr(obj, "threat_count", None)
        if annotated is not None:
            return annotated
        return obj.threats.count()


class ThreatSourceSerializer(serializers.ModelSerializer):
    """Read-only serializer for ThreatSource reference data."""

    class Meta:
        model = ThreatSource
        fields = [
            "id",
            "slug",
            "name",
            "description",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "slug",
            "name",
            "description",
            "created_at",
            "updated_at",
        ]
