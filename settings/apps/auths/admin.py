from django.contrib import admin

# Register your models here.
from .models import (
    MyUser,
    Transaction
)

admin.site.register(MyUser)
admin.site.register(Transaction)