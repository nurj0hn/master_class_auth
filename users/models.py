from copy import deepcopy
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.validators import validate_email
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken


class UserManager(BaseUserManager):
    def create_superuser(self, username, password):
        user = self.model(username=username)
        user.set_password(password)
        user.is_superuser = True
        user.is_verified = True
        user.save()
        return user

    def create_user(self, email, password):
        user = self.model(email=self.normalize_email(email))
        user.set_password(password)
        user.save()
        return user

    def get_by_natural_key(self, username):
        case_insensitive_username_field = '{}__iexact'.format(self.model.USERNAME_FIELD)
        return self.get(**{case_insensitive_username_field: username})


class User(AbstractBaseUser, PermissionsMixin):
    class Meta:
        db_table = 'user'

    USERNAME_FIELD = 'username'

    objects = UserManager()
    
    username = models.CharField('username', max_length=50, unique=True, help_text=_('Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.'),)
    password = models.CharField('Пароль', max_length=128, null=True, blank=True)
    date_joined = models.DateTimeField('Дата регистрации', auto_now_add=True)


    is_verified = models.BooleanField("Польверждение пользователя", default=False)
    is_active = models.BooleanField('Активный', default=True)
    is_superuser = models.BooleanField('Суперпользователь', default=False)
    name = models.CharField('username', max_length=50, null=True, blank=True)
    

    def __str__(self):
        title = self.username or self.email
        return str(title)

    @property
    def is_staff(self):
        return self.is_superuser

    def has_module_perms(self, module, *args, **kwargs):
        if not self.is_active:
            return False
        if self.is_superuser:
            return True
        return False

    def has_perm(self, permission, *args, **kwargs):
        if not self.is_active:
            return False
        if self.is_superuser:
            return True
        return False

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

    class Meta:
        verbose_name = "Пользователь"
        verbose_name_plural = "Пользователи"