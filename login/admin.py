from django.contrib import admin
from .models import User, OTP, LoginAttempt

# Register the custom User model
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('mobile', 'first_name', 'last_name', 'email', 'is_active', 'is_staff', 'date_joined')
    search_fields = ('mobile', 'first_name', 'last_name', 'email')
    list_filter = ('is_active', 'is_staff', 'date_joined')


# Register the OTP model
@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = ('mobile', 'code', 'is_used', 'created_at', 'expires_at')
    search_fields = ('mobile', 'code')
    list_filter = ('is_used', 'created_at', 'expires_at')


# Register the LoginAttempt model
@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'username', 'attempt_type', 'timestamp')
    search_fields = ('ip_address', 'username', 'attempt_type')
    list_filter = ('attempt_type', 'timestamp')
