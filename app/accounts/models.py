from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otpauth_url = models.CharField(max_length=225, blank=True, null=True)
    qr_code = models.ImageField(upload_to="qrcode/",blank=True, null=True)
    secret_key=models.CharField(max_length=16, blank=True, null=True)

    def __str__(self):
        return self.user.username