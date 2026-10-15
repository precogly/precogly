from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("packs", "0002_pendingtaxonomyoverlay"),
    ]

    operations = [
        migrations.AddField(
            model_name="librarypack",
            name="icon_svg",
            field=models.TextField(
                blank=True,
                default="",
                help_text="Inline SVG markup for the pack's icon, loaded from pack.yaml's icon: path.",
            ),
        ),
    ]
