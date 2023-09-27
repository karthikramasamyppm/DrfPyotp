from io import BytesIO
from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import authenticate
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK
)
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from django.core.files.base import ContentFile
from django.utils.crypto import get_random_string

from app import settings
from .models import *
import pyotp
import qrcode
import cv2
import base64
import requests
from urllib.parse import urljoin, quote_plus


# Create your views here.


    
@api_view(["POST"])
def login(request):
    username = request.data.get("username")
    password = request.data.get("password")
    if username is None or password is None:
        return Response({'error': 'Please provide both username and password'},
                        status=HTTP_400_BAD_REQUEST)
    user = authenticate(username=username, password=password)
    if not user:
        return Response({'error': 'Invalid Credentials'},
                        status=HTTP_404_NOT_FOUND)
    token, _ = Token.objects.get_or_create(user=user)
    return Response({'token': token.key},
                    status=HTTP_200_OK)


class HelloView(APIView):
    permission_classes = (IsAuthenticated,)            

    def get(self, request):
      
        content = {'message': 'Hello, World!'}
        return Response(content)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def enable_2fa(request):
    user = request.user.id
    print(user)
    # print(request.build_absolute_uri('/')[:-1])
   
    # Generate a secret key for the user
    secret_key = pyotp.random_base32()
    # print(secret_key)

    user=User.objects.filter(id=user).values('username').first()
    # print(user)

    otp_url = pyotp.totp.TOTP(secret_key).provisioning_uri(user["username"], issuer_name='verifylogin')
    stream = BytesIO()
    image = qrcode.make(f"{otp_url}")
    image.save(stream)
    qr_code = ContentFile(stream.getvalue(), name=f"qr{get_random_string(10)}.png")

    profile = UserProfile(user_id= request.user.id,otpauth_url=otp_url,secret_key=secret_key,qr_code=qr_code)
    profile.save()
    qrcode_dis=UserProfile.objects.filter(user_id=request.user.id).values('qr_code').first()
    print(qrcode_dis,"@@@@@@@@@@@@@@@@@@@@")
    result=qrcode_dis["qr_code"]
    dict_res={
        "url":otp_url,
        "image":request.build_absolute_uri('/')[:-1]+settings.MEDIA_URL+""+result
    }


    return Response({'otpauth_url': dict_res}, status=status.HTTP_201_CREATED)


class VerifyOTP(APIView):
    permission_classes = (IsAuthenticated,)            

    def post(self, request, *args, **kwargs):
        user = request.user.id
        otp = request.data.get('otp')

        # Get the OTP secret for the user
        user_profile=UserProfile.objects.filter(user_id=user).values('user__username','secret_key').first()
     
        totp = pyotp.TOTP(user_profile['secret_key'])
        print(totp.now())
        if totp.verify(otp):
            return Response({'message': 'OTP is valid',"result":user_profile['user__username']}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'OTP is invalid'}, status=status.HTTP_400_BAD_REQUEST)