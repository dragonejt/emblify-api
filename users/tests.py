from unittest.mock import MagicMock, patch
from django.test import TestCase
from django.test.utils import ignore_warnings
from django.utils.crypto import get_random_string
from rest_framework.test import APITestCase
from users import models, views

# Create your tests here.

ignore_warnings(message="No directory at", module="whitenoise.base").enable()

# Discord Integration


class DiscordIntegrationTests(TestCase):
    discord_integration = models.DiscordIntegration()
    exchange_code = {
        "access_token": get_random_string(40),
        "token_type": "Bearer",
        "expires_in": 604800,
        "refresh_token": get_random_string(40),
        "scope": "identify"
    }
    user_info = {
        "id": get_random_string(18),
        "username": get_random_string(10),
        "email": get_random_string(5) + "@test.com"
    }

    @patch("users.models.requests")
    def test_create(self, mock_requests: MagicMock) -> None:
        mock_requests.post.return_value.status_code = views.status.HTTP_200_OK
        mock_requests.post.return_value.json.return_value = self.exchange_code
        mock_requests.get.return_value.status_code = views.status.HTTP_200_OK
        mock_requests.get.return_value.json.return_value = self.user_info

        code = get_random_string(30)

        self.discord_integration.create(code, "mobile")

        self.assertEqual(
            self.discord_integration.user_id, self.user_info["id"])
        self.assertEqual(
            self.discord_integration.user_name, self.user_info["username"])
        self.assertEqual(
            self.discord_integration.user_email, self.user_info["email"])
        mock_requests.post.assert_called_with(models.ENDPOINT+"/oauth2/token", data={
            'client_id': models.CLIENT_ID,
            'client_secret': models.CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': models.MOBILE_OAUTH_REDIRECT
        }, headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        mock_requests.get.assert_called_with(models.ENDPOINT+"/users/@me", headers={
            "Authorization": "Bearer " + self.exchange_code["access_token"]
        })

    @patch("users.models.requests")
    def test_create_from_token(self, mock_requests: MagicMock) -> None:
        mock_requests.post.return_value.status_code = views.status.HTTP_200_OK
        mock_requests.post.return_value.json.return_value = self.exchange_code
        mock_requests.get.return_value.status_code = views.status.HTTP_200_OK
        mock_requests.get.return_value.json.return_value = self.user_info

        self.discord_integration.create_from_token(
            self.exchange_code["refresh_token"])

        self.assertEqual(
            self.discord_integration.user_id, self.user_info["id"])
        self.assertEqual(
            self.discord_integration.user_name, self.user_info["username"])
        self.assertEqual(
            self.discord_integration.user_email, self.user_info["email"])
        mock_requests.post.assert_called_with(models.ENDPOINT+"/oauth2/token", data={
            'client_id': models.CLIENT_ID,
            'client_secret': models.CLIENT_SECRET,
            'grant_type': 'refresh_token',
            'refresh_token': self.exchange_code["refresh_token"]
        }, headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        mock_requests.get.assert_called_with(models.ENDPOINT+"/users/@me", headers={
            "Authorization": "Bearer " + self.exchange_code["access_token"]
        })

    def test_eq(self) -> None:
        self.assertEqual(self.discord_integration, self.discord_integration)

    @patch("users.models.requests")
    def test_exchange_code(self, mock_requests: MagicMock) -> None:
        mock_requests.post.return_value.status_code.return_value = views.status.HTTP_200_OK
        mock_requests.post.return_value.json.return_value = self.exchange_code

        code = get_random_string(30)

        self.assertEqual(self.discord_integration.exchange_code(
            code, "mobile"), self.exchange_code)
        mock_requests.post.assert_called_with(models.ENDPOINT+"/oauth2/token", data={
            'client_id': models.CLIENT_ID,
            'client_secret': models.CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': models.MOBILE_OAUTH_REDIRECT
        }, headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        })

    @patch("users.models.requests")
    def test_get_user_info(self, mock_requests: MagicMock) -> None:
        mock_requests.get.return_value.status_code = views.status.HTTP_200_OK
        mock_requests.get.return_value.json.return_value = self.user_info

        self.assertEqual(self.discord_integration.get_user_info(
            self.exchange_code["access_token"]), self.user_info)
        mock_requests.get.assert_called_with(models.ENDPOINT+"/users/@me", headers={
            "Authorization": "Bearer " + self.exchange_code["access_token"]
        })

    @patch("users.models.requests")
    def test_refresh_token(self, mock_requests: MagicMock) -> None:
        mock_requests.post.return_value.status_code.return_value = views.status.HTTP_200_OK
        mock_requests.post.return_value.json.return_value = self.exchange_code

        self.assertEqual(self.discord_integration.refresh_token(
            self.exchange_code["refresh_token"]), self.exchange_code)
        mock_requests.post.assert_called_with(models.ENDPOINT+"/oauth2/token", data={
            'client_id': models.CLIENT_ID,
            'client_secret': models.CLIENT_SECRET,
            'grant_type': 'refresh_token',
            'refresh_token': self.exchange_code["refresh_token"]
        }, headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        })


class TestHelperFunctions(TestCase):
    exchange_code = {
        "access_token": get_random_string(40),
        "token_type": "Bearer",
        "expires_in": 604800,
        "refresh_token": get_random_string(40),
        "scope": "identify"
    }
    user_info = {
        "id": get_random_string(18),
        "username": get_random_string(10),
        "email": get_random_string(5) + "@test.com"
    }

    def test_get_user_from_discord(self) -> None:
        discord_integration = models.DiscordIntegration()
        discord_integration.user_id = self.user_info["id"]
        discord_integration.user_name = self.user_info["username"]
        discord_integration.user_email = self.user_info["email"]
        discord_integration.save()

        user = views.create_user(discord_integration.user_name,
                                 discord_integration.user_email, discord_integration=discord_integration)

        self.assertIsNotNone(views.get_user_from_discord(discord_integration))
        self.assertEqual(views.get_user_from_discord(
            discord_integration), user)

    def test_create_user(self) -> None:
        user = views.create_user(
            self.user_info["username"], self.user_info["email"])

        self.assertIsNotNone(user)
        self.assertEqual(user, views.User.objects.get(
            username=self.user_info["username"], email=self.user_info["email"]))

    def test_valid_username(self) -> None:
        user = views.create_user(
            self.user_info["username"], self.user_info["email"])

        self.assertFalse(views.valid_username(user.username))

        for invalid_username in views.CUSTOM_URLS:
            self.assertFalse(views.valid_username(invalid_username))

        self.assertTrue(get_random_string(10))

    def test_token_hash(self) -> None:
        user = views.create_user(
            self.user_info["username"], self.user_info["email"])
        token = views.Token.objects.create(user=user).key

        self.assertEqual(token, views.hash_to_token(
            user.username, views.token_to_hash(token)))


class TestAPIViews(APITestCase):
    exchange_code = {
        "access_token": get_random_string(40),
        "token_type": "Bearer",
        "expires_in": 604800,
        "refresh_token": get_random_string(40),
        "scope": "identify"
    }
    user_info = {
        "id": get_random_string(18),
        "username": get_random_string(10),
        "email": get_random_string(5) + "@test.com"
    }

    def test_read_unauthorized(self) -> None:
        views.create_user(self.user_info["username"], self.user_info["email"])

        response = self.client.get("/user/"+self.user_info["username"], format="json")

        self.assertEqual(response.status_code, views.status.HTTP_401_UNAUTHORIZED)
    
    def test_read_authorized(self) -> None:
        user = views.create_user(self.user_info["username"], self.user_info["email"])
        token = views.Token.objects.create(user=user).key
        emblify_user = views.EmblifyUser.objects.get(user=user)

        response = self.client.get("/user/"+self.user_info["username"], format="json", HTTP_AUTHORIZATION="Token "+token)

        self.assertEqual(response.status_code, views.status.HTTP_200_OK)
        self.assertEquals(response.json(), {
            "username": user.username,
            "is_private": emblify_user.is_private
        })

    def test_read_me(self) -> None:
        discord_integration = views.DiscordIntegration()
        discord_integration.user_id = self.user_info["id"]
        discord_integration.user_name = self.user_info["username"]
        discord_integration.user_email = self.user_info["email"]
        discord_integration.save()
        user = views.create_user(self.user_info["username"], self.user_info["email"], discord_integration=discord_integration)
        token = views.Token.objects.create(user=user).key
        emblify_user = views.EmblifyUser.objects.get(user=user)

        response = self.client.get("/user/@me", format="json", HTTP_AUTHORIZATION="Token "+token)

        self.assertEqual(response.status_code, views.status.HTTP_200_OK)
        self.assertEquals(response.json(), {
            "username": user.username,
            "is_private": emblify_user.is_private,
            "discord_id": emblify_user.discord_integration.user_id
        })
