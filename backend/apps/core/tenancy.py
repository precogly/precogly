"""Whether a model's rows belong to one organization or to every installation.

Precogly serves several organizations from one database, and the rule keeping them
apart has been written once per viewset — as a join from the caller's memberships to
whatever the model happens to hang off. Measured across the 61 models in `apps/`, 38
of the 43 that reach `Organization` do so by more than one path, all 38 through a
nullable foreign key somewhere along the way, and three models that held customer
data — `Zone`, `Boundary`, `VerificationTest` — reached it by no forward path
at all (zones and boundaries now reach it through `blueprint.threat_model`). So each
of those joins is a guess, nothing checks it, and six cross-tenant defects have been
found by hand (#226, #227, #404, #405, #406, #258).

The fact that no join can recover is which kind of row a table holds. That is what
this module records, and `apps.core.checks` is what makes recording it compulsory.
Declaring is all it does: no column moves and no query changes. Giving tenant-owned
models a non-null `organization` column, and enforcing the boundary against it, are
separate and later.

Usage, as a plain class attribute beside the fields:

```python
class Orgsystem(TimestampedModel):
    tenancy = Tenancy.TENANT_OWNED

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    ...
```
"""

import enum


class Tenancy(enum.Enum):
    """Who a row belongs to.

    A model declares exactly one of these. `apps.core.checks` refuses to start with a
    model that declares none, so the question cannot be skipped by forgetting it.
    """

    TENANT_OWNED = "tenant-owned"
    """Every row belongs to exactly one organization.

    Reading a row as a member of another organization is a leak, and writing one is
    worse. These are the models that gain a non-null `organization` column when the
    boundary becomes a column; today it is still whatever join each viewset writes.
    """

    SHARED_REFERENCE = "shared-reference"
    """Every installation holds the same rows, and every organization may read them.

    Library packs, taxonomies, and the reference data imported from them. There is no
    organization to scope by and no leak to prevent — an unscoped queryset here is
    correct, which is why a check that only asks "is this queryset scoped" cannot be
    the whole answer.
    """

    MIXED = "mixed"
    """The table holds both kinds of row, and nothing in it says which is which.

    A defect. It is recorded rather than fixed here only because fixing it is a
    migration; `MIXED_MODELS` below pins the six that exist so the set can shrink and
    cannot grow.

    `StandardFramework` is the clearest case and says so in its own field:

        help_text="Populated for user-created internal standards. "
                  "NULL for global pack-sourced frameworks."

    `ThreatLibrary`, `CountermeasureLibrary`, `ComponentLibrary`, and
    `DFDTemplatesLibrary` repeat the shape with `source_pack` — "Pack this item came
    from (null = custom or legacy)". Where the tenant-authored rows carry no owner,
    every organization reads them; #405 is that bug on `StandardFramework`.

    One table is not itself the defect, and there is a real reason these are shaped
    this way: one table is one foreign-key target. `ThreatLibrary` has six incoming
    foreign keys and `StandardRequirement` five, so splitting them turns each into a
    nullable pair or a generic relation, and an `InstanceThreat` would have to
    record which of two tables it points at.

    The defect is that ownership is *inferred* from a key that exists for another
    purpose. `source_pack` records provenance and `threat_model` records attachment;
    reading either as "and therefore nobody owns this row" is the step nothing checks.
    Removing that inference is what these six are owed — by splitting them, or by
    giving them an explicit owner column that means only that. Which of the two is per
    table, and the incoming-foreign-key counts above are the argument.
    """


# The models that hold both kinds of row today. A pinned list rather than a derived
# one: `Tenancy.MIXED` is a defect being carried, and the point of naming it here is
# that `apps.core.tests.test_tenancy_check` fails if the set grows. Removing an entry
# means the table was split or given an explicit owner column, and that is the only
# direction this list may move.
MIXED_MODELS = frozenset(
    {
        "compliance.StandardFramework",
        "compliance.StandardRequirement",
        "diagrams.DFDTemplatesLibrary",
        "systems.ComponentLibrary",
        "threats.CountermeasureLibrary",
        "threats.ThreatLibrary",
    }
)
