# Generated by Django 5.1 on 2024-08-25 15:03

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('student_management_app', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='attendance',
            name='attendance_date',
            field=models.DateField(),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='first_name',
            field=models.CharField(blank=True, max_length=150, verbose_name='first name'),
        ),
        migrations.AlterField(
            model_name='leavereportstaff',
            name='leave_status',
            field=models.IntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='leavereportstudent',
            name='leave_status',
            field=models.IntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='staffs',
            name='employee_no',
            field=models.TextField(default=123456, max_length=6),
        ),
        migrations.AlterField(
            model_name='staffs',
            name='registration_date',
            field=models.DateField(auto_now=True),
        ),
        migrations.AlterField(
            model_name='staffs',
            name='registration_no',
            field=models.TextField(default=123456, max_length=6),
        ),
        migrations.AlterField(
            model_name='students',
            name='address',
            field=models.TextField(default='Planet Earth'),
        ),
        migrations.AlterField(
            model_name='students',
            name='lrn',
            field=models.TextField(default=123456789102, max_length=12),
        ),
        migrations.CreateModel(
            name='StudentResult',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('subject_exam_marks', models.FloatField(default=0)),
                ('subject_assignment_marks', models.FloatField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('student_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='student_management_app.students')),
                ('subject_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='student_management_app.subjects')),
            ],
        ),
    ]