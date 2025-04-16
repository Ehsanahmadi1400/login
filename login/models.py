from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from django.utils import timezone
from datetime import timedelta

from django.core.exceptions import ValidationError
import re


def validate_mobile(mobile):
    pattern = r'^09\d{9}$'
    if not re.match(pattern, mobile):
        raise ValidationError("Mobile number must start with '09' and be exactly 11 digits long.")


class UserManager(BaseUserManager):
    def create_user(self, mobile, password=None, **extra_fields):
        if not mobile:
            raise ValueError("Mobile number is required")
        user = self.model(mobile=mobile, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, mobile, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(mobile, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    mobile = models.CharField(max_length=11, unique=True)
    first_name = models.CharField(max_length=50, blank=True)
    last_name = models.CharField(max_length=50, blank=True)
    email = models.EmailField(blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = 'mobile'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.mobile

    def clean(self):
        super().clean()  # Call the parent class's clean method
        validate_mobile(self.mobile)


class OTP(models.Model):
    mobile = models.CharField(max_length=15, unique=True)
    code = models.CharField(max_length=6)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(blank=True, null=True)

    objects = models.Manager()

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=10)  # 10 minutes expiry time
        super().save(*args, **kwargs)

    def is_expired(self):
        return timezone.now() > self.expires_at


class LoginAttempt(models.Model):
    ip_address = models.GenericIPAddressField()
    username = models.CharField(max_length=150, blank=True, null=True)
    attempt_type = models.CharField(max_length=20)  # 'login' or 'register'
    timestamp = models.DateTimeField(auto_now_add=True)

    objects = models.Manager()
