import os
from django.db import models
from django.contrib.auth.models import User
import requests


# Create your models here.

ENDPOINT = "https://discord.com/api"
CLIENT_ID = "986703621771100220"
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI")


class DiscordIntegration(models.Model):
    user_id = models.CharField(max_length=100)
    user_email = models.CharField(max_length=100)
    user_name = models.CharField(max_length=100)

    def __str__(self) -> str:
        return self.user_id

    def create(self, code: str, ext: str):
        access_token = self.exchange_code(code, ext)["access_token"]
        user_info = self.get_user_info(access_token)
        self.user_id = user_info["id"]
        self.user_email = user_info["email"]
        self.user_name = user_info["username"]

    def equals(self, discord_integration: "DiscordIntegration") -> bool:
        if type(self) == type(discord_integration) and self.user_id == discord_integration.user_id:
            return True
        return False

    def exchange_code(self, code: str, ext: str) -> str:
        response = requests.post(ENDPOINT+"/oauth2/token", data={
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI + ext
        }, headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        response.raise_for_status()
        return response.json()

    def get_user_info(self, access_token: str) -> dict:
        response = requests.get(ENDPOINT+"/users/@me", headers={
            "Authorization": "Bearer " + access_token
        })
        response.raise_for_status()
        return response.json()


class EmblifyUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    is_private = models.BooleanField(default=False)
    discord_integration = models.OneToOneField(
        DiscordIntegration, on_delete=models.CASCADE, null=True, blank=True)
    reddit_username = models.CharField(max_length=100)

    def __str__(self) -> str:
        return str(self.user)
