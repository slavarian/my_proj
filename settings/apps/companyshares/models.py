from django.db import models

# Create your models here.

class Company(models.Model):
    name = models.CharField(
        verbose_name='название компании',
        max_length=200
    )
    date_create = models.DateTimeField(
        verbose_name= 'дата создания компании',

    )


class Shares(models.Model):
    name = models.CharField(
        verbose_name='акция',
        max_length=200
    )
    price = models.DecimalField(
        verbose_name='цена',
        max_digits=11,
        decimal_places=2,
        default=0
    )
    company = models.OneToOneField(
        verbose_name='какой компании пренадлежит акция',
        related_name='company',
        to=Company,
        on_delete=models.PROTECT
    )

