from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('risk', '0065_bksec_preset_pa_and_rule_source'),
    ]

    operations = [
        migrations.AddField(
            model_name='ticketnode',
            name='is_test',
            field=models.BooleanField(db_index=True, default=False, verbose_name='Is Test'),
        ),
    ]
