from django.contrib import admin

# Register your models here.

from .models import (
    Company,
    Shares
)

admin.site.register(Company)
admin.site.register(Shares)