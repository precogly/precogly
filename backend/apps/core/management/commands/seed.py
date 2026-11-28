"""
Seed the database with demo data for new contributors.

Creates a superuser, demo organization, imports the three demo packs bundled
with the app (STRIDE, a subset of OWASP ASVS and a small AWS pack), and creates
two sample threat models from the AWS pack's templates. Fills the first sample
model's Risk Register. Never touches the network: the full packs come from the
pack catalog on the Libraries page.

Also creates a second organization and a member who is not on the security team, so
that the demo database can exhibit multi-tenancy. See _create_second_org for why that
is not optional.

Usage:
    python manage.py seed
    python manage.py seed --force  (re-import packs even if they exist)
"""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from apps.diagrams.canvas import normalize_canvas
from apps.diagrams.models import DFD, DFDTemplatesLibrary
from apps.diagrams.services import sync_dfd_nodes_to_components
from apps.organizations.models import (
    Organization,
    OrganizationMember,
    Team,
    TeamMembership,
)
from apps.packs.models import LibraryPack
from apps.packs.services import get_libraries_path, import_pack_from_path, validate_pack
from apps.threat_models.models import ThreatModel, ThreatModelLibraryPack
from apps.threats.services import create_risk, create_risk_response

User = get_user_model()

DEMO_EMAIL = "admin@precogly.dev"
# Published in the setup docs on purpose, so a new contributor can sign in to a
# freshly seeded database. It grants nothing beyond a local demo organization.
DEMO_PASSWORD = "admin123"  # noqa: S105
DEMO_ORG_NAME = "Demo Organization"
DEMO_TEAM_NAME = "My Team"

# A member of the demo organization whose role is not security team.
ANALYST_EMAIL = "analyst@precogly.dev"

# A second organization, and a user who belongs to it and to nothing else.
SECOND_ORG_NAME = "Contoso Financial"
SECOND_ORG_TEAM_NAME = "Payments"
SECOND_ORG_EMAIL = "contoso@precogly.dev"

# The demo packs bundled under libraries/packs. Import order matters:
# taxonomies first, then standards, then the threat library that maps to both.
TAXONOMY_PACKS = ["demo-taxonomies/stride-taxonomy"]
STANDARD_PACKS = ["demo-standards/demo-asvs"]
FULL_PACKS = ["demo-threat-libraries/demo-aws"]

SAMPLE_THREAT_MODELS = [
    {
        "name": "Sample AWS Serverless Web App",
        "description": "A sample serverless web app with CloudFront, API Gateway, Lambda, DynamoDB, and S3.",
        "template_slug": "demo-aws/aws-serverless-web-app",
        "criticality": "HIGH",
    },
    {
        "name": "Sample AWS SaaS Tenant Isolation",
        "description": (
            "A sample multi-tenant SaaS app isolating tenants with Cognito, "
            "scoped IAM policies, KMS and partitioned data stores."
        ),
        "template_slug": "demo-aws/aws-saas-multi-tenant",
        "criticality": "HIGH",
    },
]

# Something for the second organization to own. A listing that is empty for every caller
# cannot tell organization scoping apart from an empty database.
SECOND_ORG_THREAT_MODELS = [
    {
        "name": "Payments API",
        "description": "Card capture and settlement path for the Contoso payments API.",
        "template_slug": None,
        "criticality": "CRITICAL",
    },
]

# Risks for the Risk Register, on the first sample threat model.
#
# Ratings are not written here. `create_risk` rates these pairs with the model's
# 5x5 matrix engine the same way the application does, so demo risks cannot
# drift from what the engine would produce.
# The old `response` column became a status and one RiskResponse row
# (section 4.7): mitigate is the spec's reduce.
SAMPLE_RISK_RESPONSES = {
    None: ("identified", None),
    "mitigate": ("assessed", "reduce"),
    "transfer": ("transferred", "transfer"),
    "avoid": ("assessed", "avoid"),
    "accept": ("accepted", "accept"),
}

SAMPLE_RISKS = {
    None: [
        ("Unauthenticated internal Lambda invoke URL", "certain", "severe"),
        ("Public S3 bucket exposes customer documents", "likely", "severe"),
        ("No request throttling on the auth endpoint", "likely", "major"),
        ("Lambda role grants wildcard S3 permissions", "possible", "severe"),
        ("Secrets in plaintext Lambda env variables", "possible", "major"),
        ("Request bodies with PII retained in logs", "unlikely", "major"),
    ],
    "mitigate": [
        ("SQL injection in the order lookup handler", "likely", "severe"),
        ("WAF rules miss newer OWASP categories", "certain", "major"),
        ("JWT signature unchecked on the internal path", "likely", "major"),
        ("Cross-tenant read via unvalidated bucket key", "certain", "moderate"),
        ("Known RCE in a bundled Lambda dependency", "likely", "moderate"),
        ("No rate limit on credential stuffing", "certain", "minor"),
        ("Stack traces disclosed in API errors", "possible", "moderate"),
    ],
    # Carried by a provider contract or an insurer.
    "transfer": [
        ("Payment processor outage halts settlement", "unlikely", "severe"),
        ("OpenSearch cluster loses an availability zone", "unlikely", "major"),
        ("CDN mis-routes traffic on a config push", "possible", "minor"),
        ("Identity provider certificate expires", "unlikely", "moderate"),
    ],
    # The activity is dropped rather than controlled.
    "avoid": [
        ("Shared root credentials in the deploy pipeline", "likely", "severe"),
        ("Customer data copied to the analytics sandbox", "possible", "severe"),
        ("Direct database access from developer laptops", "possible", "major"),
    ],
    # Raising either value on any of these lifts it onto the first page, so the
    # Accept column stops being empty there.
    "accept": [
        ("Internal status page exposes service names", "rare", "negligible"),
        ("Staging bucket keeps unversioned objects", "rare", "negligible"),
        ("Admin console lacks a session idle timeout", "rare", "negligible"),
        ("Developer docs list internal hostnames", "rare", "negligible"),
    ],
}


class Command(BaseCommand):
    help = "Seed database with demo data for development"

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Re-import packs even if they already exist",
        )

    def handle(self, *args, **options):
        force = options["force"]

        org = self._create_org()
        user = self._get_or_create_user(DEMO_EMAIL, superuser=True)
        team = self._setup_membership(org, user)
        self._import_packs(force)
        sample_models = self._create_sample_threat_models(
            org, team, user, SAMPLE_THREAT_MODELS
        )
        self._create_analyst(org, team)
        # Before _connect_packs_to_threat_models, so Contoso's threat model gets the
        # imported packs on the same run rather than on the next one.
        second_org_sample_models = self._create_second_org()
        self._connect_packs_to_threat_models(sample_models + second_org_sample_models)
        self._seed_risks(org)
        self._report_accounts()

    def _create_org(self):
        # A migration may have already created a primary org. Use it if so.
        org = Organization.objects.filter(is_primary=True).first()
        if org:
            if org.name != DEMO_ORG_NAME:
                org.name = DEMO_ORG_NAME
                org.save(update_fields=["name"])
            self.stdout.write(f"Using existing primary organization: {org.name}")
        else:
            org = Organization.objects.create(
                name=DEMO_ORG_NAME,
                plan=Organization.Plan.FREE,
                is_primary=True,
            )
            self.stdout.write(
                self.style.SUCCESS(f"Created organization: {DEMO_ORG_NAME}")
            )

        self._ensure_default_team(org, DEMO_TEAM_NAME)
        return org

    def _ensure_default_team(self, org, name):
        """Return the organization's default team, creating it as `name` if absent."""
        team = Team.objects.filter(organization=org, is_default=True).first()
        if team:
            return team
        return Team.objects.create(organization=org, name=name, is_default=True)

    def _get_or_create_user(self, email, superuser=False):
        """Create a demo account holding DEMO_PASSWORD, or return the existing one.

        Username is the lookup rather than email: it is the unique field on the default
        user model, and every seeded account uses the address for both.
        """
        label = "Superuser" if superuser else "User"
        existing = User.objects.filter(username=email).first()
        if existing:
            self.stdout.write(f"{label} already exists: {email}")
            return existing

        create = (
            User.objects.create_superuser if superuser else User.objects.create_user
        )
        user = create(username=email, email=email, password=DEMO_PASSWORD)
        self.stdout.write(self.style.SUCCESS(f"Created {label.lower()}: {email}"))
        return user

    def _setup_membership(
        self,
        org,
        user,
        org_role=OrganizationMember.Role.SECURITY_TEAM,
        team=None,
        team_role=TeamMembership.Role.LEAD,
    ):
        """Give the user a role in the organization and on one of its teams.

        Both rows may already exist, the post_save signal creates the organization
        membership for new users, and an earlier seed may have created either with a
        different role, so the role is asserted rather than assumed. Defaults to the
        team lead on the security team, which is what the demo superuser wants.
        """
        membership, _ = OrganizationMember.objects.get_or_create(
            organization=org,
            user=user,
            defaults={"role": org_role},
        )
        if membership.role != org_role:
            membership.role = org_role
            membership.save()

        team = team or Team.objects.filter(organization=org, is_default=True).first()
        if team:
            team_membership, _ = TeamMembership.objects.get_or_create(
                team=team,
                user=user,
                defaults={"role": team_role},
            )
            if team_membership.role != team_role:
                team_membership.role = team_role
                team_membership.save()

        return team

    def _create_analyst(self, org, team):
        """Add a member of the demo organization who is not on the security team.

        IsSecurityTeam gates writes and leaves reads open. With the superuser as the only
        account there is no caller for whom that distinction is visible, so a role check
        and no role check at all return the same answer for every request the demo
        database can make.
        """
        user = self._get_or_create_user(ANALYST_EMAIL)
        self._setup_membership(
            org,
            user,
            org_role=OrganizationMember.Role.MEMBER,
            team=team,
            team_role=TeamMembership.Role.MEMBER,
        )

    def _create_second_org(self):
        """Create a second organization whose only member belongs to no other.

        Seeded unconditionally rather than behind a flag, because the bugs it exposes are
        invisible by construction on a single-organization database: every queryset is
        scoped to the one organization the one user belongs to, so a missing scope and a
        correct scope return the same rows. Nobody can ask for a fixture whose absence
        they have no way to notice.
        """
        org, created = Organization.objects.get_or_create(
            name=SECOND_ORG_NAME,
            # is_primary stays False: the constraint on Organization permits one primary
            # organization and the demo organization holds it.
            defaults={"plan": Organization.Plan.FREE, "is_primary": False},
        )
        if created:
            self.stdout.write(
                self.style.SUCCESS(f"Created organization: {SECOND_ORG_NAME}")
            )
        else:
            self.stdout.write(f"Using existing organization: {SECOND_ORG_NAME}")

        team = self._ensure_default_team(org, SECOND_ORG_TEAM_NAME)
        user = self._get_or_create_user(SECOND_ORG_EMAIL)
        self._setup_membership(org, user, team=team)

        # Undo the auto-enrolment in the demo organization that create_personal_workspace
        # performs for every new user. Left in place, this account is a genuine member of
        # both organizations, so a listing returning both organizations' rows is correct
        # behaviour rather than a leak, and the two stop being distinguishable, which is
        # the whole thing this account exists to distinguish.
        OrganizationMember.objects.filter(user=user).exclude(organization=org).delete()
        TeamMembership.objects.filter(user=user).exclude(team=team).delete()

        return self._create_sample_threat_models(
            org, team, user, SECOND_ORG_THREAT_MODELS
        )

    def _import_packs(self, force):
        libraries_path = get_libraries_path()
        if not libraries_path.exists():
            # Loud on purpose. Returning here seeds every organization, user and
            # sample threat model while importing no packs at all, and a database
            # whose libraries are empty looks seeded from the outside.
            raise CommandError(
                f"Libraries path not found: {libraries_path}. "
                "Set LIBRARIES_PATH to the directory holding packs/."
            )

        all_packs = TAXONOMY_PACKS + STANDARD_PACKS + FULL_PACKS
        for pack_slug in all_packs:
            pack_path = libraries_path / pack_slug
            if not pack_path.exists():
                # Loud for the same reason as above: carrying on would create
                # the sample threat models with no diagram behind them.
                raise CommandError(
                    f"Demo pack not found: {pack_path}. The seed needs every "
                    "pack in TAXONOMY_PACKS, STANDARD_PACKS and FULL_PACKS."
                )

            # Validate before importing
            validation_result = validate_pack(pack_path)
            if not validation_result.success or validation_result.warnings:
                for error in validation_result.errors:
                    self.stdout.write(self.style.ERROR(f"  Error: {error.message}"))
                for warning in validation_result.warnings:
                    self.stdout.write(
                        self.style.WARNING(f"  Warning: {warning.message}")
                    )
                self.stdout.write(
                    self.style.WARNING(f"Skipped: {pack_slug}, validation failed")
                )
                continue

            result = import_pack_from_path(
                pack_path=pack_path,
                force=force,
                selected_overlays=None,  # Load all overlays
                skip_validation=True,  # Already validated above
            )
            if result.success:
                self.stdout.write(self.style.SUCCESS(f"Imported: {pack_slug}"))
            else:
                self.stdout.write(
                    self.style.WARNING(f"Skipped: {pack_slug}, {result.message}")
                )

    def _create_sample_threat_models(self, org, team, user, samples):
        """Create (or find) each sample threat model and return every one of them.

        The return value is what `_connect_packs_to_threat_models` uses to limit
        itself to the threat models this command is actually responsible for,
        so it must include a model this run found already existing, not only
        the ones it just created.
        """
        threat_models = []
        for sample in samples:
            name = sample["name"]
            existing = ThreatModel.objects.filter(name=name, organization=org).first()
            if existing:
                self.stdout.write(f"Threat model already exists: {name}")
                threat_models.append(existing)
                continue

            # A null template_slug means the sample deliberately has no diagram, which is
            # not the same as a slug that failed to resolve. Only the latter is a warning.
            template_slug = sample["template_slug"]
            template = None
            if template_slug:
                template = DFDTemplatesLibrary.objects.filter(
                    qualified_slug=template_slug
                ).first()
                if not template:
                    self.stdout.write(
                        self.style.WARNING(
                            f"DFD template not found: {template_slug}. "
                            "Threat model created without diagram."
                        )
                    )

            criticality = getattr(ThreatModel.Criticality, sample["criticality"])

            if not template:
                threat_model = ThreatModel.objects.create(
                    organization=org,
                    owning_team=team,
                    created_by=user,
                    name=name,
                    description=sample["description"],
                    criticality=criticality,
                )
                threat_models.append(threat_model)
                self.stdout.write(self.style.SUCCESS(f"Created: {name}"))
                continue

            threat_model = ThreatModel.objects.create(
                organization=org,
                owning_team=team,
                created_by=user,
                name=name,
                description=sample["description"],
                criticality=criticality,
            )

            # Connect all imported packs before generating threats
            imported_packs = LibraryPack.objects.all()
            ThreatModelLibraryPack.objects.bulk_create(
                [
                    ThreatModelLibraryPack(threat_model=threat_model, library_pack=pack)
                    for pack in imported_packs
                ],
                ignore_conflicts=True,
            )

            blueprint = threat_model.default_blueprint
            dfd = DFD.objects.create(
                name="Data Flow Diagram 1",
                diagram_type=template.diagram_type,
                blueprint=blueprint,
                template_library=template,
                canvas_data=normalize_canvas(template.canvas_data),
                is_primary=True,
                updated_by=user,
            )

            sync_result = sync_dfd_nodes_to_components(dfd, blueprint)
            components_count = sync_result.get("created_count", 0)
            threats_count = sync_result.get("threats_generated", 0)

            self.stdout.write(
                self.style.SUCCESS(
                    f"Created: {name} "
                    f"({components_count} components, {threats_count} threats)"
                )
            )
            threat_models.append(threat_model)

        return threat_models

    def _seed_risks(self, org):
        """Fill the first sample threat model's Risk Register.

        Keyed on whether that model already has risks, not on whether this run
        created it. `_create_sample_threat_models` skips a model that exists, so
        a step hung off model creation would never run on a database that has
        been seeded before, which is every database that needs this.
        """
        threat_model = ThreatModel.objects.filter(
            name=SAMPLE_THREAT_MODELS[0]["name"], organization=org
        ).first()
        if not threat_model:
            self.stdout.write(
                self.style.WARNING(
                    f"No threat model named {SAMPLE_THREAT_MODELS[0]['name']}. "
                    "Risk Register left empty."
                )
            )
            return

        if threat_model.risks.exists():
            self.stdout.write(f"Risks already exist: {threat_model.name}")
            return

        owner = User.objects.filter(username=DEMO_EMAIL).first()
        assignee = User.objects.filter(username=ANALYST_EMAIL).first()

        risks = []
        for response, entries in SAMPLE_RISKS.items():
            status, strategy = SAMPLE_RISK_RESPONSES[response]
            for name, likelihood, impact in entries:
                position = len(risks)
                risk = create_risk(
                    threat_model,
                    rating_inputs={"likelihood": likelihood, "impact": impact},
                    name=name,
                    status=status,
                    # Leave every third risk unowned. An owner column filled
                    # on every row never renders its empty state.
                    owner=owner if position % 3 else None,
                    assigned_to=assignee if position % 4 == 0 else None,
                )
                if strategy:
                    create_risk_response(risk, strategy=strategy)
                risks.append(risk)

        self.stdout.write(
            self.style.SUCCESS(f"Created {len(risks)} risks on {threat_model.name}")
        )

    def _connect_packs_to_threat_models(self, threat_models):
        """Ensure all imported packs are connected to the given threat models.

        `threat_models` must be exactly the sample threat models this command itself
        creates or finds, never `ThreatModel.objects.all()`. `seed` is meant to run on
        every container start so a fresh deploy's libraries are never empty, but on a
        database that already holds real, non-sample threat models, an unscoped version
        of this call attaches every library pack in the database to every one of them,
        including other customers' own client-specific packs, every single run.
        """
        all_packs = LibraryPack.objects.all()
        if not all_packs.exists() or not threat_models:
            return

        associations = [
            ThreatModelLibraryPack(threat_model=tm, library_pack=pack)
            for tm in threat_models
            for pack in all_packs
        ]
        created = ThreatModelLibraryPack.objects.bulk_create(
            associations, ignore_conflicts=True
        )
        count = len(created)
        if count:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Connected {all_packs.count()} packs to {len(threat_models)} sample threat models"
                )
            )

    def _report_accounts(self):
        """Print the seeded logins as a table.

        This is the last thing `docker compose up` prints before the dev server starts,
        and it has to be findable in a scrollback that already holds a dozen pack-import
        lines. There are three accounts now rather than one, and which organization and
        role each holds is the whole point of seeding them, so the summary says so.

        Rows are read back out of the database rather than off the constants above, so
        the table cannot report a role or an organization that was not actually written.
        """
        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("Seed complete!"))
        self.stdout.write("")
        self.stdout.write("  URL:      http://localhost:5173")
        self.stdout.write(f"  Password: {DEMO_PASSWORD}   (every account below)")
        self.stdout.write("")
        self.stdout.write(
            self.style.MIGRATE_HEADING(f"  {'EMAIL':<22} {'ORGANIZATION':<20} ROLE")
        )

        memberships = (
            OrganizationMember.objects.filter(
                user__username__in=[DEMO_EMAIL, ANALYST_EMAIL, SECOND_ORG_EMAIL]
            )
            .select_related("organization", "user")
            .order_by("user__username")
        )
        for membership in memberships:
            role = membership.get_role_display()
            if membership.user.is_superuser:
                role += " (superuser)"
            self.stdout.write(
                f"  {membership.user.username:<22} "
                f"{membership.organization.name:<20} {role}"
            )
        self.stdout.write("")
