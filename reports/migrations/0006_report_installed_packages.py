from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reports', '0005_alter_report_options'),
    ]

    operations = [
        migrations.AddField(
            model_name='report',
            name='installed_packages',
            field=models.TextField(blank=True, null=True),
        ),
    ]
