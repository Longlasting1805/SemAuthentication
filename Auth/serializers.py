from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
# from rest_registration.validators import  domain_validator
from django.utils.encoding import force_text
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from Auth.models import CustomUser

User = get_user_model()

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only= True)
    
    class Meta:
        model = User
        fields = ('id', 'username', 'password', 'email')

        
        def create(self, validated_data):
            password = validated_data.pop('password', None)
            user = User.objects.create_user(**validated_data,  password=password)
            user.set_password(password)
            user.save()
            return user
        
class UserLoginSerializer(serializers.Serializer):
      username = serializers.CharField()
      password = serializers.CharField()

      def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if not username:
            raise serializers.ValidationError("Username is required.")
    
        if not password:
            raise serializers.ValidationError("Password is required.")
        
        user = authenticate(username=username, password=password)
        if not user:
            raise serializers.ValidationError("Unable to log in with provided credentials.")

        data['user'] = user  # Make sure 'user' key is added to validated_data
        return data

      def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user  


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




