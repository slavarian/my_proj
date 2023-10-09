from django import forms
from auths.models import MyUser


class UserProfileForm(forms.ModelForm):
    class Meta:
        model = MyUser
        fields = ('email','nickname','shares')