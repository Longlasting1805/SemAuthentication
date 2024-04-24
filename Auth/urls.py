from django.urls import path
from .views import (
    UserRegistrationAPIView,
    UserLoginAPIView,
    PasswordResetAPIView,
    EmailVerificationAPIView,
    ResetTokenAPIView,
)

urlpatterns = [
    path('register/', UserRegistrationAPIView.as_view(), name='user_register'),
    path('login/', UserLoginAPIView.as_view(), name='user_login'),
    path('reset-password/',  PasswordResetAPIView.as_view(), name='password_reset'),
    path('verify-email/',  EmailVerificationAPIView.as_view(), name='verify_email'),
    path('get-reset-token/',  ResetTokenAPIView.as_view(), name='get_reset_token')



]