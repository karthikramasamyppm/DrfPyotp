from django.urls import path
from accounts import views

urlpatterns = [
    path('hello/', views.HelloView.as_view(), name='hello'), #class based view
    path('login/', views.login),#fuction based view
    path('enable-2fa/', views.enable_2fa, name='enable-2fa'),
    path('verify-otp/', views.VerifyOTP.as_view(), name='VerifyOTP'),
]