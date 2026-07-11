"""
Remove stale columns from packs_librarypack and packs_librarypackdependency.

These columns were removed from the models but never had a corresponding migration.
Existing databases still have these NOT NULL columns, causing INSERT failures for
any new pack or dependency.
"""

from django.db import migrations


STALE_COLUMNS = {
    "packs_librarypack": [
        "tier", "source", "content", "industries",
        "repository_url", "documentation_url", "icon_url",
        "install_count", "is_published", "published_at",
    ],
    "packs_librarypackdependency": [
        "version_constraint", "is_optional",
    ],
}


def remove_columns_if_exist(apps, schema_editor):
    """Drop stale columns only if they exist (safe for fresh installs)."""
    connection = schema_editor.connection
    for table, stale_columns in STALE_COLUMNS.items():
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = %s", [table]
            )
            existing = {row[0] for row in cursor.fetchall()}

        columns_to_drop = [c for c in stale_columns if c in existing]
        if columns_to_drop:
            drops = ", ".join(f"DROP COLUMN {c}" for c in columns_to_drop)
            with connection.cursor() as cursor:
                cursor.execute(f"ALTER TABLE {table} {drops}")


def clean_phantom_migration(apps, schema_editor):
    """Remove the phantom 0002_add_standard_requirement_mapping record if present."""
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            "DELETE FROM django_migrations "
            "WHERE app = 'packs' AND name = '0002_add_standard_requirement_mapping'"
        )


class Migration(migrations.Migration):

    dependencies = [
        ("packs", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(
            remove_columns_if_exist,
            migrations.RunPython.noop,
        ),
        migrations.RunPython(
            clean_phantom_migration,
            migrations.RunPython.noop,
        ),
    ]
