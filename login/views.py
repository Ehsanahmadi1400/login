from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from django.contrib.auth import authenticate
from .models import User, OTP, LoginAttempt
from django.core.exceptions import ObjectDoesNotExist
from django.utils.crypto import get_random_string
from datetime import timedelta
from django.db.models import Count
from rest_framework_simplejwt.tokens import RefreshToken

from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication


def is_blocked(ip, mobile=None, attempt_type='register'):
    # Check for failed attempts within the last hour
    time_threshold = timezone.now() - timedelta(hours=1)
    attempts = LoginAttempt.objects.filter(
        ip_address=ip,
        attempt_type=attempt_type,
        timestamp__gte=time_threshold
    )
    if mobile:
        attempts = attempts.filter(username=mobile)

    return attempts.count() >= 3


class CheckMobileView(APIView):
    def post(self, request): # noqa
        mobile = request.data.get('mobile')
        ip = request.META.get('REMOTE_ADDR')

        if is_blocked(ip, mobile, 'register'):
            return Response({'detail': 'Too many attempts. Try again later.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        if User.objects.filter(mobile=mobile).exists():
            return Response({'registered': True}, status=status.HTTP_200_OK)
        else:
            code = get_random_string(length=6, allowed_chars='0123456789')
            OTP.objects.create(mobile=mobile, code=code)
            return Response({'registered': False, 'otp_code': code}, status=status.HTTP_200_OK)


class LoginView(APIView):
    def post(self, request): # noqa
        mobile = request.data.get('mobile')
        password = request.data.get('password')
        ip = request.META.get('REMOTE_ADDR')

        if is_blocked(ip, mobile, 'login'):
            return Response({'detail': 'Too many failed attempts. Try again later.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        user = authenticate(request, mobile=mobile, password=password)
        if user:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            return Response({'detail': 'Login successful', 'access': access_token, 'refresh': str(refresh)},
                                   status=status.HTTP_200_OK)
        else:
            LoginAttempt.objects.create(ip_address=ip, username=mobile, attempt_type='login')
            return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)



class VerifyOTPView(APIView):
    def post(self, request): # noqa
        mobile = request.data.get('mobile')
        code = request.data.get('code')
        ip = request.META.get('REMOTE_ADDR')

        # Check if the user is blocked from attempting registration
        if is_blocked(ip, mobile, 'register'):
            return Response({'detail': 'Too many attempts. Try again 1 hour later.'},
                            status=status.HTTP_429_TOO_MANY_REQUESTS
                            )

        try:
            otp = OTP.objects.filter(mobile=mobile, code=code, is_used=False).latest('created_at')

            if otp.is_expired():
                return Response({'detail': 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)

        except ObjectDoesNotExist:
            # Register the failed attempt for the given mobile
            LoginAttempt.objects.create(ip_address=ip, username=mobile, attempt_type='register')
            return Response({'detail': 'Invalid or expired code'}, status=status.HTTP_400_BAD_REQUEST)

        # Mark OTP as used
        otp.is_used = True
        otp.save()

        # Create or update the user
        user, created = User.objects.get_or_create(mobile=mobile)
        return Response({'detail': 'OTP verified, continue registration'}, status=status.HTTP_200_OK)


class CompleteRegistrationView(APIView):
    def post(self, request): # noqa
        mobile = request.data.get('mobile')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        email = request.data.get('email')
        password = request.data.get('password')

        try:
            user = User.objects.get(mobile=mobile)
        except ObjectDoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        user.first_name = first_name
        user.last_name = last_name
        user.email = email
        user.set_password(password)
        user.save()

        return Response({'detail': 'Registration complete'}, status=status.HTTP_200_OK)


class ProfileView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request): # noqa
        user = request.user
        return Response({
            'mobile': user.mobile,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'detail': 'You are logged in.'
        }, status=status.HTTP_200_OK)
