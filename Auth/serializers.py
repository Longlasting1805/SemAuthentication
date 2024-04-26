from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from rest_registration.validators import  domain_validator
from django.utils.encoding import force_text
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator

User = get_user_model()

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only= True, validators=[domain_validator])
    
    class Meta:
        model = User
        fields = '__all__'
        
        def create(self, validated_data):
            password = validated_data.pop('password')
            user = User.objects.create_user(**validated_data)
            user.set_password(password)
            user.save()
            return user
        
class UserLoginSerializer(serializers.Serializer):
    # email = serializers.EmailField()
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True)
    # is_admin = serializers.BooleanField(default=False)
    # is_student = serializers.BooleanField(default=False)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')
        # is_admin = data.get('is_admin', False)
        # is_student = data.get('is_student', False)

        if not username or not password:
             raise serializers.ValidationError("Both username and password are required.")
        
        user = authenticate(username=username, password=password)
        if not user:
            raise serializers.ValidationError("Unable to log in with provided credentials.")
        
        data['user'] = user
       

        # data['is_admin'] = is_admin
        # data['is_student'] = is_student

        return data

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




