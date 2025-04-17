from django.core.validators import RegexValidator
from rest_framework import serializers
from .models import User


class MobileSerializer(serializers.Serializer):
    mobile = serializers.CharField(
        max_length=11,
        validators=[
            RegexValidator(
                regex=r'^09\d{9}$',
                message="Mobile number must start with 09 and be exactly 11 digits.",
            )
        ]
    )
