from django.urls import path
from . import views

urlpatterns = [
    path('auth/check/', views.CheckMobileView.as_view(), name='check_mobile'),
    path('auth/login/', views.LoginView.as_view(), name='login'),
    path('auth/register/verify/', views.VerifyOTPView.as_view(), name='verify_otp'),
    path('auth/register/details/', views.CompleteRegistrationView.as_view(), name='complete_registration'),
    path('profile/', views.ProfileView.as_view(), name='profile'),
]
