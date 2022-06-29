from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from .models import EmblifyUser, DiscordIntegration

class EmblifyUserInline(admin.StackedInline):
    model = EmblifyUser
    can_delete = False

# Define a new User admin
class UserAdmin(BaseUserAdmin):
    inlines = [EmblifyUserInline]

class DiscordIntegrationAdmin(admin.ModelAdmin):
    fields = ["user_id", "user_name", "user_email"]

# Re-register UserAdmin
admin.site.unregister(User)
admin.site.register(User, UserAdmin)
admin.site.register(DiscordIntegration, DiscordIntegrationAdmin)
