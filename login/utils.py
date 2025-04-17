from datetime import timedelta
from django.utils import timezone

from login.models import LoginAttempt


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
