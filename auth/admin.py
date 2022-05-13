from django.contrib.admin.apps import AdminConfig
from django.contrib.admin.sites import AdminSite


class StaffAdmin(AdminSite):

    def has_permission(self, request):
        return request.user.is_active and (request.user.is_staff
                                           or request.user.is_manager
                                           or request.user.is_superuser)


staff_admin = StaffAdmin(name='staff-admin')
