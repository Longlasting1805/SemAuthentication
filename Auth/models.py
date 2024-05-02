from django.db import models
from django.contrib.auth.models import AbstractUser


# Create your models here.

class CustomUser(AbstractUser):
    first_name = models.CharField(max_length=100, unique=False, blank=False, null=False)
    last_name = models.CharField(max_length=100, unique=False, blank=False, null=False)
    email = models.EmailField()
    username = models.CharField(max_length=100, unique=True, blank=False, null=False)
    date_of_birth = models.DateField(auto_now_add=True)
    phone_number = models.CharField(max_length=100, unique=False, blank=False, null=False)
    is_admin = models.BooleanField(default=False)
    is_student = models.BooleanField(default=False)

    # USERNAME_FIELD = 'email'

    def is_administrator(self):
        return self.is_admin

    def is_student(self):
        return self.is_student
