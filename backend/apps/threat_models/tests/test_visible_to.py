"""Who may read which threat models.

`ThreatModelQuerySet.visible_to` is the entire read boundary. `CanWrite` and
`IsSecurityTeam` both return True for safe methods (`apps/core/permissions.py`), so
nothing else narrows a read.

`account()` below deletes what the account was given on creation, and that is
load-bearing rather than tidiness. `create_personal_workspace`
(`apps/organizations/signals.py`) puts every new user in the primary organization, or,
where there is no primary organization — which is every test database — in a workspace
of its own as **security team**. Left alone, every fixture here would satisfy the
security-team branch, and the plain-member cases would pass while testing nothing.
"""

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.organizations.models import (
    Organization,
    OrganizationMember,
    Team,
    TeamMembership,
)
from apps.threat_models.models import ThreatModel

User = get_user_model()


def account(email):
    """A user holding no membership at all, whatever the signal granted."""
    user = User.objects.create_user(username=email, email=email, password="testpass123")
    user.organization_memberships.all().delete()
    user.team_memberships.all().delete()
    return user


def names(queryset):
    return sorted(model.name for model in queryset)


class VisibleToTests(TestCase):
    """The four cases the branch structure distinguishes."""

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Kestrel", domain="kestrel.test")
        cls.other = Organization.objects.create(name="Contoso", domain="contoso.test")

        cls.platform = Team.objects.create(organization=cls.org, name="Platform")
        cls.payments = Team.objects.create(organization=cls.org, name="Payments")

        cls.platform_model = ThreatModel.objects.create(
            organization=cls.org, name="Ingest pipeline", owning_team=cls.platform
        )
        cls.payments_model = ThreatModel.objects.create(
            organization=cls.org, name="Card vault", owning_team=cls.payments
        )
        # `owning_team` is nullable for records that predate the field, and there is no
        # team on them to check, so every member of the organization reads them.
        cls.unowned_model = ThreatModel.objects.create(
            organization=cls.org, name="Legacy billing", owning_team=None
        )
        cls.other_org_model = ThreatModel.objects.create(
            organization=cls.other, name="Contoso ledger", owning_team=None
        )

    def test_a_member_of_the_owning_team_reads_its_models_and_the_unowned_ones(self):
        user = account("platform@kestrel.test")
        OrganizationMember.objects.create(
            organization=self.org, user=user, role="member"
        )
        TeamMembership.objects.create(team=self.platform, user=user)

        assert names(ThreatModel.objects.visible_to(user)) == [
            "Ingest pipeline",
            "Legacy billing",
        ]

    def test_a_member_on_no_team_reads_only_the_unowned_ones(self):
        user = account("newjoiner@kestrel.test")
        OrganizationMember.objects.create(
            organization=self.org, user=user, role="member"
        )

        assert names(ThreatModel.objects.visible_to(user)) == ["Legacy billing"]

    def test_security_team_reads_every_model_in_the_organization(self):
        user = account("appsec@kestrel.test")
        OrganizationMember.objects.create(
            organization=self.org, user=user, role="security_team"
        )

        assert names(ThreatModel.objects.visible_to(user)) == [
            "Card vault",
            "Ingest pipeline",
            "Legacy billing",
        ]

    def test_an_organization_you_do_not_belong_to_is_invisible(self):
        # The outer bound, and the one that would matter most if it broke: no branch
        # below it can widen the set past the caller's own organizations.
        user = account("outsider@contoso.test")
        OrganizationMember.objects.create(
            organization=self.other, user=user, role="security_team"
        )

        assert names(ThreatModel.objects.visible_to(user)) == ["Contoso ledger"]

    def test_an_account_with_no_membership_reads_nothing(self):
        assert (
            list(ThreatModel.objects.visible_to(account("nobody@kestrel.test"))) == []
        )


class SecurityTeamIsNotScopedToAnOrganizationTests(TestCase):
    """precogly/precogly#209, pinned as it behaves rather than as it should.

    `visible_to` asks whether the user is on *any* organization's security team, so
    the answer carries into organizations where they are a plain member. The account
    below is security team at Contoso and an ordinary member at Kestrel, and reads
    every Kestrel model including the two owned by teams it does not belong to.

    This test exists to make the fix visible when it lands: when #209 is settled, this
    fails, and the expected set becomes the unowned model alone. It is not an
    endorsement of the behaviour.
    """

    @classmethod
    def setUpTestData(cls):
        cls.org = Organization.objects.create(name="Kestrel", domain="kestrel.test")
        cls.other = Organization.objects.create(name="Contoso", domain="contoso.test")
        cls.team = Team.objects.create(organization=cls.org, name="Platform")

        ThreatModel.objects.create(
            organization=cls.org, name="Ingest pipeline", owning_team=cls.team
        )
        ThreatModel.objects.create(
            organization=cls.org, name="Legacy billing", owning_team=None
        )

    def test_security_team_at_one_organization_reads_everything_at_another(self):
        user = account("contractor@contoso.test")
        OrganizationMember.objects.create(
            organization=self.other, user=user, role="security_team"
        )
        OrganizationMember.objects.create(
            organization=self.org, user=user, role="member"
        )

        assert names(ThreatModel.objects.visible_to(user)) == [
            "Ingest pipeline",
            "Legacy billing",
        ]
