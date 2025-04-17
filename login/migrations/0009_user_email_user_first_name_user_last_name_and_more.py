# Generated by Django 4.2.2 on 2025-04-17 04:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0008_remove_user_email_remove_user_first_name_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='email',
            field=models.EmailField(blank=True, max_length=254),
        ),
        migrations.AddField(
            model_name='user',
            name='first_name',
            field=models.CharField(blank=True, max_length=50),
        ),
        migrations.AddField(
            model_name='user',
            name='last_name',
            field=models.CharField(blank=True, max_length=50),
        ),
        migrations.DeleteModel(
            name='Profile',
        ),
    ]
