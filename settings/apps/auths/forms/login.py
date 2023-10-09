from django import forms 
from django.contrib.auth import authenticate



class LoginForm(forms.Form):
    email = forms.EmailField(label='Email', max_length=100)
    password = forms.CharField(label='Пароль', widget=forms.PasswordInput)