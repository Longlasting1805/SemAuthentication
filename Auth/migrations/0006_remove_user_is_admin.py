# Generated by Django 5.0.4 on 2024-05-17 12:47

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Auth', '0005_user_delete_customuser'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='is_admin',
        ),
    ]