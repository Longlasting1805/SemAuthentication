from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model

# Create your models here.

class CustomUser(AbstractUser):
    # user = models.OneToOneField(User, on_delete=models.CASCADE)
# #     first_name = models.CharField(max_length=100, unique=False, blank=False, null=False)
# #     last_name = models.CharField(max_length=100, unique=False, blank=False, null=False)
# #     email = models.EmailField()
#     username = models.CharField(max_length=100, unique=True, blank=False, null=False)
#     #   date_of_birth = models.DateField(auto_now_add=True)
#     #   phone_number = models.CharField(max_length=100, unique=False, blank=False, null=False)
#     #   is_admin = models.BooleanField(default=False)
#     #   is_student = models.BooleanField(default=False)
#     #   is_active =  models.BooleanField(default=True)

#     # USERNAME_FIELD = 'email'
#     REQUIRED_FIELDS = ['user']
#     USERNAME_FIELD = 'username'

    # def is_admin(self):
    #     return self.is_admin

    # def is_student(self):
    #     return self.is_student

# CustomUser = get_user_model()    
 pass
  
