"""Use a package-scoped table name for SocialIdentity.

The v0.16.0 migration created ``social_identity``. That table name is too
generic for a reusable Django package because it can collide with consuming
apps. Rename it to ``blockauth_social_identity`` while preserving the model
and data.
"""

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("blockauth", "0004_social_identity"),
    ]

    operations = [
        migrations.AlterModelTable(
            name="socialidentity",
            table="blockauth_social_identity",
        ),
    ]
