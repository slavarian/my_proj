from rest_framework import serializers
from .models import MyUser
from django.contrib.auth import get_user_model

class RegSerializer(serializers.ModelSerializer):
    class Meta:
        model = MyUser
        fields = ('email', 'nickname','password')


class LoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = MyUser
        fields = ('email','password')

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model =  get_user_model()
        fields = ('id', 'email', 'nickname', 'shares', 'balance', 'currency')
