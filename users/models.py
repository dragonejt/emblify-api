import os
from django.db import models
from django.contrib.auth.models import User
import requests


# Create your models here.

ENDPOINT = "https://discord.com/api"
CLIENT_ID = "986703621771100220"
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
WEB_OAUTH_REDIRECT = "https://emblify.me/oauth"
MOBILE_OAUTH_REDIRECT = "emblify://oauth"


class DiscordIntegration(models.Model):
    user_id = models.CharField(max_length=100)
    user_email = models.CharField(max_length=100)
    user_name = models.CharField(max_length=100)

    def __str__(self) -> str:
        return self.user_id

    def equals(self, discord_integration: "DiscordIntegration") -> bool:
        if isinstance(discord_integration, type(self)) and self.user_id == discord_integration.user_id and self.user_name == discord_integration.user_name and self.user_email == discord_integration.user_email:
            return True
        return False

    def create(self, code: str, platform: str) -> str:
        token_response = self.exchange_code(code, platform)
        access_token = token_response["access_token"]
        refresh_token = token_response["refresh_token"]

        user_info = self.get_user_info(access_token)
        self.user_id = user_info["id"]
        self.user_email = user_info["email"]
        self.user_name = user_info["username"]

        return refresh_token

    def create_from_token(self, refresh_token: str) -> str:
        token_response = self.refresh_token(refresh_token)
        access_token = token_response["access_token"]
        refresh_token = token_response["refresh_token"]

        user_info = self.get_user_info(access_token)
        self.user_id = user_info["id"]
        self.user_email = user_info["email"]
        self.user_name = user_info["username"]

        return refresh_token

    def exchange_code(self, code: str, platform: str) -> str:
        response = requests.post(ENDPOINT+"/oauth2/token", data={
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': MOBILE_OAUTH_REDIRECT if platform == "mobile" else WEB_OAUTH_REDIRECT
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

    def refresh_token(self, refresh_token: str) -> dict:
        r = requests.post(ENDPOINT+"/oauth2/token", data={
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token
        }, headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        r.raise_for_status()
        return r.json()


class EmblifyUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    is_private = models.BooleanField(default=False)
    discord_integration = models.OneToOneField(
        DiscordIntegration, on_delete=models.CASCADE, null=True, blank=True)
    reddit_username = models.CharField(max_length=100)

    def __str__(self) -> str:
        return str(self.user)
