from django import forms
from typing import Any , Dict
from django.core.exceptions import ValidationError

class RegisterForm(forms.Form):
    email = forms.EmailField(label='Почта', max_length=200)
    nickname = forms.CharField(label="Ваш ник", max_length=100)
    password = forms.CharField(label='Пароль', min_length=6)
    password2 = forms.CharField(label='Повторите пароль', min_length=6)

    def clean(self) -> Dict[str, Any]:
        return super().clean()
    
    def clean_email(self):
        data:str = self.cleaned_data['email']
        if '@mail' in data:
            raise ValidationError('fuuuu!')
        return data
    
    def clean_password2(self) -> Dict[str, Any]:
        if self.cleaned_data['password'] != self.cleaned_data['password2']:
            raise ValidationError('пароли не совпадают')
        return self.cleaned_data