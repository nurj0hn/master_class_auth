from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group
from django.utils.translation import gettext_lazy as _

from auth.admin import staff_admin
from .models import User

class CustomUserAdmin(UserAdmin):
    model = User
    list_display = ('username', 'is_verified', 'is_active',)
    list_filter = ('is_superuser',)
    list_editable = ('is_verified',)
    readonly_fields = ('date_joined',)


admin.site.register(User, CustomUserAdmin)
admin.site.unregister(Group)

admin.site.site_header = _("GeekTech Admin")


class StaffUserAdmin(CustomUserAdmin):

    def has_delete_permission(self, request, obj=None):
        return False

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


staff_admin.register(User, StaffUserAdmin)