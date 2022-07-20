from unittest.mock import MagicMock, patch
from django.test import TestCase
from django.test.utils import ignore_warnings
from django.utils.crypto import get_random_string
from rest_framework.test import APITestCase
from users import models, views

# Create your tests here.

ignore_warnings(message="No directory at", module="whitenoise.base").enable()

# Discord Integration

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
    "password": get_random_string(15),
    "email": get_random_string(5) + "@test.com"
}


class DiscordIntegrationTests(TestCase):
    discord_integration = models.DiscordIntegration()

    @patch("users.models.requests")
    def test_create(self, mock_requests: MagicMock) -> None:
        mock_requests.post.return_value.status_code = views.status.HTTP_200_OK
        mock_requests.post.return_value.json.return_value = exchange_code
        mock_requests.get.return_value.status_code = views.status.HTTP_200_OK
        mock_requests.get.return_value.json.return_value = user_info

        code = get_random_string(30)

        self.discord_integration.create(code, "mobile")

        self.assertEqual(
            self.discord_integration.user_id, user_info["id"])
        self.assertEqual(
            self.discord_integration.user_name, user_info["username"])
        self.assertEqual(
            self.discord_integration.user_email, user_info["email"])
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
            "Authorization": "Bearer " + exchange_code["access_token"]
        })

    @patch("users.models.requests")
    def test_create_from_token(self, mock_requests: MagicMock) -> None:
        mock_requests.post.return_value.status_code = views.status.HTTP_200_OK
        mock_requests.post.return_value.json.return_value = exchange_code
        mock_requests.get.return_value.status_code = views.status.HTTP_200_OK
        mock_requests.get.return_value.json.return_value = user_info

        self.discord_integration.create_from_token(
            exchange_code["refresh_token"])

        self.assertEqual(
            self.discord_integration.user_id, user_info["id"])
        self.assertEqual(
            self.discord_integration.user_name, user_info["username"])
        self.assertEqual(
            self.discord_integration.user_email, user_info["email"])
        mock_requests.post.assert_called_with(models.ENDPOINT+"/oauth2/token", data={
            'client_id': models.CLIENT_ID,
            'client_secret': models.CLIENT_SECRET,
            'grant_type': 'refresh_token',
            'refresh_token': exchange_code["refresh_token"]
        }, headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        mock_requests.get.assert_called_with(models.ENDPOINT+"/users/@me", headers={
            "Authorization": "Bearer " + exchange_code["access_token"]
        })

    @patch("users.models.requests")
    def test_exchange_code(self, mock_requests: MagicMock) -> None:
        mock_requests.post.return_value.status_code.return_value = views.status.HTTP_200_OK
        mock_requests.post.return_value.json.return_value = exchange_code

        code = get_random_string(30)

        self.assertEqual(self.discord_integration.exchange_code(
            code, "mobile"), exchange_code)
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
        mock_requests.get.return_value.json.return_value = user_info

        self.assertEqual(self.discord_integration.get_user_info(
            exchange_code["access_token"]), user_info)
        mock_requests.get.assert_called_with(models.ENDPOINT+"/users/@me", headers={
            "Authorization": "Bearer " + exchange_code["access_token"]
        })

    @patch("users.models.requests")
    def test_refresh_token(self, mock_requests: MagicMock) -> None:
        mock_requests.post.return_value.status_code.return_value = views.status.HTTP_200_OK
        mock_requests.post.return_value.json.return_value = exchange_code

        self.assertEqual(self.discord_integration.refresh_token(
            exchange_code["refresh_token"]), exchange_code)
        mock_requests.post.assert_called_with(models.ENDPOINT+"/oauth2/token", data={
            'client_id': models.CLIENT_ID,
            'client_secret': models.CLIENT_SECRET,
            'grant_type': 'refresh_token',
            'refresh_token': exchange_code["refresh_token"]
        }, headers={
            'Content-Type': 'application/x-www-form-urlencoded'
        })


class TestHelperFunctions(TestCase):
    def test_get_user_from_discord(self) -> None:
        discord_integration = models.DiscordIntegration()
        discord_integration.user_id = user_info["id"]
        discord_integration.user_name = user_info["username"]
        discord_integration.user_email = user_info["email"]
        discord_integration.save()

        user = views.create_user(
            user_info["username"], user_info["email"], user_info["password"], discord_integration)

        self.assertIsNotNone(views.get_user_from_discord(discord_integration))
        self.assertEqual(views.get_user_from_discord(
            discord_integration), user)

    def test_create_user(self) -> None:
        user = views.create_user(
            user_info["username"], user_info["email"], user_info["password"])

        self.assertIsNotNone(user)
        self.assertEqual(user, views.User.objects.get(
            username=user_info["username"], email=user_info["email"]))

    def test_valid_username(self) -> None:
        user = views.create_user(
            user_info["username"], user_info["email"], user_info["password"])

        self.assertFalse(views.valid_username(user.username))

        for invalid_username in views.CUSTOM_URLS:
            self.assertFalse(views.valid_username(invalid_username))

        self.assertTrue(get_random_string(10))

    def test_token_hash(self) -> None:
        user = views.create_user(
            user_info["username"], user_info["email"], user_info["password"])
        token = views.Token.objects.create(user=user)

        self.assertEqual(token.key, views.hash_to_token(
            user.username, views.token_to_hash(token.key)))


class TestAPIViews(APITestCase):
    def test_read_authorized(self) -> None:
        user = views.create_user(
            user_info["username"], user_info["email"], user_info["password"])
        token = views.Token.objects.create(user=user)
        emblify_user = views.EmblifyUser.objects.get(user=user)

        response = self.client.get(
            "/user/"+user_info["username"], format="json", HTTP_AUTHORIZATION="Token "+token.key)

        self.assertEqual(response.status_code, views.status.HTTP_200_OK)
        self.assertEqual(response.json(), {
            "username": user.username,
            "is_private": emblify_user.is_private
        })

    def test_read_me(self) -> None:
        discord_integration = views.DiscordIntegration()
        discord_integration.user_id = user_info["id"]
        discord_integration.user_name = user_info["username"]
        discord_integration.user_email = user_info["email"]
        discord_integration.save()
        user = views.create_user(user_info["username"], user_info["email"],
                                 user_info["password"], discord_integration=discord_integration)
        token = views.Token.objects.create(user=user)
        emblify_user = views.EmblifyUser.objects.get(user=user)

        response = self.client.get(
            "/user/@me", format="json", HTTP_AUTHORIZATION="Token "+token.key)

        self.assertEqual(response.status_code, views.status.HTTP_200_OK)
        self.assertEqual(response.json(), {
            "username": user.username,
            "is_private": emblify_user.is_private,
            "discord_id": emblify_user.discord_integration.user_id
        })

    @patch("users.models.requests")
    def test_oauth_login(self, mock_requests):
        discord_integration = models.DiscordIntegration()
        discord_integration.user_id = user_info["id"]
        discord_integration.user_name = user_info["username"]
        discord_integration.user_email = user_info["email"]
        discord_integration.save()

        user = views.create_user(
            user_info["username"], user_info["email"], user_info["password"], discord_integration)
        code = get_random_string(30)

        mock_requests.post.return_value.status_code = views.status.HTTP_200_OK
        mock_requests.post.return_value.json.return_value = exchange_code
        mock_requests.get.return_value.status_code = views.status.HTTP_200_OK
        mock_requests.get.return_value.json.return_value = user_info

        response = self.client.post("/user/oauth", data={
            "code": code,
            "platform": "web"
        }, format="json")

        self.assertEqual(response.status_code, views.status.HTTP_200_OK)
        self.assertEqual(response.json(), {
            "username": user_info["username"],
            "access_token": views.Token.objects.get(user=user).key,
            "active": user.is_active,
            "discord_id": user_info["id"]
        })

    @patch("users.models.requests")
    def test_oauth_link(self, mock_requests):
        user = views.create_user(
            user_info["username"], user_info["email"], user_info["password"])

        mock_requests.post.return_value.status_code = views.status.HTTP_200_OK
        mock_requests.post.return_value.json.return_value = exchange_code
        mock_requests.get.return_value.status_code = views.status.HTTP_200_OK
        mock_requests.get.return_value.json.return_value = user_info

        code = get_random_string(30)
        token = views.Token.objects.create(user=user)

        response = self.client.post("/user/oauth", data={
            "code": code,
            "platform": "web"
        }, format="json", HTTP_AUTHORIZATION="Token "+token.key)

        self.assertEqual(response.status_code, views.status.HTTP_200_OK)
        self.assertEqual(response.json(), {
            "username": user_info["username"],
            "access_token": views.Token.objects.get(user=user).key,
            "active": user.is_active,
            "discord_id": user_info["id"]
        })

    @patch("users.models.requests")
    def test_oauth_no_user(self, mock_requests):
        mock_requests.post.return_value.status_code = views.status.HTTP_200_OK
        mock_requests.post.return_value.json.return_value = exchange_code
        mock_requests.get.return_value.status_code = views.status.HTTP_200_OK
        mock_requests.get.return_value.json.return_value = user_info

        code = get_random_string(30)

        response = self.client.post("/user/oauth", data={
            "code": code,
            "platform": "web"
        }, format="json")

        self.assertEqual(response.status_code,
                         views.status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {
            "discord_token": exchange_code["refresh_token"]
        })

    def test_login(self):
        user = views.create_user(
            user_info["username"], user_info["email"], user_info["password"])
        token = views.Token.objects.create(user=user)

        response = self.client.post("/user/login", data={
            "username": user_info["username"],
            "password": user_info["password"]
        }, format="json")

        self.assertEqual(response.status_code, views.status.HTTP_200_OK)
        self.assertEqual(response.json(), {
            "username": user_info["username"],
            "access_token": token.key,
            "Active": user.is_active
        })

    @patch("users.models.requests")
    def test_register(self, mock_requests):
        mock_requests.post.return_value.status_code = views.status.HTTP_200_OK
        mock_requests.post.return_value.json.return_value = exchange_code
        mock_requests.get.return_value.status_code = views.status.HTTP_200_OK
        mock_requests.get.return_value.json.return_value = user_info

        response = self.client.post("/user/register", data={
            "username": user_info["username"],
            "password": user_info["password"],
            "email": user_info["email"],
            "discord_token": exchange_code["refresh_token"]
        }, format="json")

        self.assertEqual(response.status_code, views.status.HTTP_201_CREATED)
        self.assertEqual(response.json()["username"], user_info["username"])

    def test_activate(self):
        user = views.create_user(
            user_info["username"], user_info["email"], user_info["password"])
        user.is_active = False
        token = views.Token.objects.create(user=user)

        response = self.client.post("/user/activate", data={
            "activation_code": get_random_string(5)
        }, format="json", HTTP_AUTHORIZATION="Token "+token.key)

        user = views.User.objects.get(
            username=user_info["username"], email=user_info["email"])

        self.assertEqual(response.status_code, views.status.HTTP_200_OK)
        self.assertTrue(user.is_active)

    def test_exchange(self):
        user = views.create_user(
            user_info["username"], user_info["email"], user_info["password"])
        token = views.Token.objects.create(user=user)

        exchange_hash = self.client.post("/user/exchange", data={
            "type": "token",
            "token": token.key
        }, format="json").data["hash"]

        exchange_token = self.client.post("/user/exchange", data={
            "type": "hash",
            "username": user_info["username"],
            "hash": exchange_hash
        }, format="json").data["token"]

        self.assertEqual(token.key, exchange_token)

    def test_logout(self):
        user = views.create_user(
            user_info["username"], user_info["email"], user_info["password"])
        token = views.Token.objects.create(user=user)

        response = self.client.get(
            "/user/logout", format="json", HTTP_AUTHORIZATION="Token "+token.key)

        self.assertEqual(response.status_code, views.status.HTTP_200_OK)
        self.assertRaises(views.Token.DoesNotExist)

    def test_unlink(self):
        discord_integration = models.DiscordIntegration()
        discord_integration.user_id = user_info["id"]
        discord_integration.user_name = user_info["username"]
        discord_integration.user_email = user_info["email"]
        discord_integration.save()

        user = views.create_user(
            user_info["username"], user_info["email"], user_info["password"], discord_integration)
        token = views.Token.objects.create(user=user)
        emblify_user = views.EmblifyUser.objects.get(user=user)

        self.assertEqual(
            len(views.DiscordIntegration.objects.filter(emblifyuser=emblify_user)), 1)

        response = self.client.delete(
            "/user/unlink", format="json", HTTP_AUTHORIZATION="Token "+token.key)

        self.assertEqual(response.status_code, views.status.HTTP_200_OK)
        self.assertEqual(
            len(views.DiscordIntegration.objects.filter(emblifyuser=emblify_user)), 0)

    def test_close(self):
        user = views.create_user(
            user_info["username"], user_info["email"], user_info["password"])
        token = views.Token.objects.create(user=user)

        response = self.client.delete(
            "/user/close", format="json", HTTP_AUTHORIZATION="Token "+token.key)

        user = views.User.objects.get(
            username=user_info["username"], email=user_info["email"])
        emblify_user = views.EmblifyUser.objects.get(user=user)

        self.assertEqual(response.status_code, views.status.HTTP_200_OK)
        self.assertFalse(user.is_active)
        self.assertTrue(emblify_user.is_private)
