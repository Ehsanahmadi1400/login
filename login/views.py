from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from .models import User, OTP, LoginAttempt
from django.core.exceptions import ObjectDoesNotExist
from django.utils.crypto import get_random_string

from rest_framework_simplejwt.tokens import RefreshToken

from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

from login.serializers import MobileSerializer
from .utils import is_blocked


class CheckMobileView(APIView):
    @swagger_auto_schema(
        operation_description="Check mobile registration status and handle OTP generation",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'mobile': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Mobile number (must start with 09 and be 11 digits)",
                ),
            },
            required=['mobile'],
        )
    )

    def post(self, request): # noqa
        serializer = MobileSerializer(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        mobile = serializer.validated_data['mobile']

        ip = request.META.get('REMOTE_ADDR')


        if is_blocked(ip, mobile, 'register'):
            return Response({'detail': 'Too many attempts. Try again 1 hour later.'},
                            status=status.HTTP_429_TOO_MANY_REQUESTS
                            )
        # Check if the user has already received an OTP
        existing_otp = OTP.objects.filter(mobile=mobile, is_used=False).first()
        if existing_otp:
            return Response({
                'registered': False,
                'detail': 'You have already used this number. Please use the verification code sent to you.',
                'otp_code': existing_otp.code  # should be removed in production
            }, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(mobile=mobile).exists():
            return Response({'registered': True}, status=status.HTTP_200_OK)
        else:
            code = get_random_string(length=6, allowed_chars='0123456789')
            OTP.objects.create(mobile=mobile, code=code)
            return Response({'registered': False, 'otp_code': code}, status=status.HTTP_200_OK)


class LoginView(APIView):
    @swagger_auto_schema(
        operation_description="Authenticate a user with their mobile number and password.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'mobile': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="User's mobile number (must start with 09 and be 11 digits)."
                ),
                'password': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="User's password."
                )
            },
            required=['mobile', 'password']
        )
    )
    def post(self, request): # noqa
        mobile = request.data.get('mobile')
        password = request.data.get('password')
        ip = request.META.get('REMOTE_ADDR')

        if is_blocked(ip, mobile, 'login'):
            return Response({'detail': 'Too many failed attempts. Try again 1 hour later.'},
                            status=status.HTTP_429_TOO_MANY_REQUESTS
                            )

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
    @swagger_auto_schema(
        operation_description="Verify the OTP code for mobile registration.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'mobile': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="The mobile number associated with the OTP (must start with 09 and be 11 digits)."
                ),
                'code': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="The 6-digit OTP code sent to the user's mobile."
                )
            },
            required=['mobile', 'code']
        )
    )
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
        return Response({'detail': 'OTP verified, continue registration'}, status=status.HTTP_200_OK
        )


class CompleteRegistrationView(APIView):
    @swagger_auto_schema(
        operation_description="Complete user registration by providing additional details and setting a password.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'mobile': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="User's mobile number (must start with 09 and be 11 digits)."
                ),
                'first_name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="User's first name."
                ),
                'last_name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="User's last name."
                ),
                'email': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="User's email address."
                ),
                'password': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="User's password."
                )
            },
            required=['mobile', 'password']
        )
    )

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


    @swagger_auto_schema(auto_schema=None) # noqa  # This hides the endpoint from Swagger
    def get(self, request): # noqa
        mobile = request.query_params.get('mobile')  # Get the 'mobile' parameter from the query string

        # If no 'mobile' is provided, return the logged-in user's profile
        if not mobile:
            user = request.user
        else:
            # Try to fetch the profile of the user with the specified mobile number
            try:
                user = User.objects.get(mobile=mobile)
            except ObjectDoesNotExist:
                return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response({
            'mobile': user.mobile,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'detail': 'You are logged in.'
        }, status=status.HTTP_200_OK)
