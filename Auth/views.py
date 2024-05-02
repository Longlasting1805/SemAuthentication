from django.shortcuts import render
# from rest_registration.api.views.verification import VerifyEmailView
from rest_framework import status
from rest_framework.response import Response
from django.http import HttpResponse
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordResetView
from django.urls import reverse
from django.core.mail import send_mail
from rest_framework.authtoken.models import Token
from Auth.models import CustomUser
from django.contrib.auth import login
from django.contrib.auth import get_user_model, authenticate
from .serializers import (
    UserRegistrationSerializer, 
    UserLoginSerializer,
    PasswordResetSerializer,
    ResetTokenSerializer,
    EmailVerificationSerializer
)

# Create your views here.

User = get_user_model

class UserRegistrationAPIView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request):
        users = CustomUser.objects.all()  # Retrieve all users from the database
        serializer = UserRegistrationSerializer(users, many=True)  # Serialize all users
        return Response(serializer.data, status=status.HTTP_200_OK) 
    
class UserLoginAPIView(APIView):
      serializer_class = UserLoginSerializer
      def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'error': 'User does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        if not user.is_active:
            return Response({'error': 'User account is not active.'}, status=status.HTTP_403_FORBIDDEN)
        
        user = authenticate(request=request, username=username, password=password)

        if user is None:
           return Response({'error': 'Invalid username or password.'}, status=status.HTTP_401_UNAUTHORIZED)
        
        token, created = Token.objects.get_or_create(user=user)

        return Response({'message': 'Login successful', 'token': token.key}, status=status.HTTP_200_OK)





class PasswordResetAPIView(PasswordResetView):   
  def post(self, request):
        serializer =  PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            is_admin = serializer.validated_data.get('is_admin', False)
            is_student = serializer.validated_data.get('is_student', False)

            try:
                user = User.objects.get(email=email, is_admin=is_admin, is_student=is_student)
            except User.DoesNotExist:
                return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

            # Generate reset token
            token = default_token_generator.make_token(user)

            # Construct password reset URL
            reset_url = reverse('password_reset_confirm')
            reset_link = f"{reset_url}?uidb64={user.pk}&token={token}"

            # Send email
            send_mail(
                'Password Reset',
                f'Click the following link to reset your password: {reset_link}',
                'from@example.com',
                [email],
                fail_silently=False,
            )

            return Response({"message": "Password reset email sent. Check your email."})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class EmailVerificationAPIView(APIView):
    serializer = EmailVerificationSerializer    

    def get(self, request):
        user = request.user
        if hasattr(request.user, 'email_verified'):
            # User is authenticated, and 'email_verified' attribute is available
            if request.user.email_verified:
                # User's email is verified
                return HttpResponse('Email is verified')
            else:
                # User's email is not verified
                return HttpResponse('Email is not verified')
        else:
            # User is authenticated but does not have the 'email_verified' attribute
            # Handle this case as needed
            return HttpResponse('User is authenticated but email verification status is unavailable')

class ResetTokenAPIView(APIView):
    def post(self, request):
        serializer = ResetTokenSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
                # send the token via email or any other method
            return Response({'token': token}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) 

