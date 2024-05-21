from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
# from rest_registration.validators import  domain_validator
from django.utils.encoding import force_text
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from Auth.models import CustomUser

User = get_user_model()
# print("user model",User)

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only= True)
    
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'password', 'email']
        # extra_field = {'password': {'write_only': {'write_only': True}}}

        
        # def create(self, validated_data):
        #     user = User(
        #     email=validated_data['email'],
        #     username=validated_data['username'],
        #     password=validated_data['password']
        # )
        #     user.set_password(validated_data['password'])
        #     user.save()
        #     return user
        
class UserLoginSerializer(serializers.Serializer):
      username = serializers.CharField(max_length=150)
      password = serializers.CharField(required=True, write_only=True)

      class Meta:
          model = CustomUser

    #   def validate(self, attrs):
    #     username = attrs['username']
    #     password = attrs['password']
    #     user = authenticate(username=username, password=password)
    #     print("user", user)
        

        # print("==========================",password)
        # print("==========================",username)

        # if username and password:
            # Check if the username and password are valid, you can customize this according to your authentication logic
            # user = authenticate(username=username, password=password)
            # print("authenticated user",user)
        
        #     if user:
        #         if not user.is_active:
        #             raise serializers.ValidationError("User account is disabled.")
        #     else:
        #         raise serializers.ValidationError("Incorrect username or password.")
        # else:
        #     raise serializers.ValidationError("Must include 'username' and 'password'.")
            # pass
         

        # data['user'] = user
        #  return data


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    is_admin = serializers.BooleanField(default=False)
    is_student = serializers.BooleanField(default=False)

class EmailVerificationSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()
    is_admin = serializers.BooleanField(default=False)
    is_student = serializers.BooleanField(default=False)

    def validate(self, data):
        uidb64 = data.get('uidb64')
        token = data.get('token')
        is_admin = data.get('is_admin', False)
        is_student = data.get('is_student', False)

        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            # If you need to handle is_admin and is_student here, you can do it
            return data

        raise serializers.ValidationError("Invalid verification link.")


class ResetTokenSerializer(serializers.Serializer):
    email = serializers.EmailField()




