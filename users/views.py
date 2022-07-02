import hashlib
from django.utils.crypto import get_random_string
from django.contrib import auth
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.authtoken.models import Token
from .models import EmblifyUser, DiscordIntegration


# Create your views here.
CUSTOM_URLS = ["oauth", "login", "register", "activate",
               "request", "logout", "update", "link", "unlink", "close"]

# API Views


@api_view(["GET"])
def read(request: Request, username: str) -> Response:
    user = get_user_from_username(username)
    user_info = {
        "username": user.username,
        "is_private": user.is_private
    }

    if request.user.username == username or user.is_private is False:
        user_info["discord_integration"] = user.discord_integration.oauth_id

    return Response(user_info, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([AllowAny])
def oauth(request: Request) -> Response:
    discord_integration = DiscordIntegration()
    discord_integration.create(request.GET["code"], "oauth")
    user = get_user_from_discord(discord_integration)
    auth.login(request, user)
    token = Token.objects.get_or_create(user=user)[0]

    return Response({
        "username": user.username,
        "Authorization": "Token",
        "access_token": token.key,
        "Activation": user.is_active
    }, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([AllowAny])
def login(request: Request) -> Response:
    user = auth.authenticate(
        request, username=request.data["username"], password=request.data["password"])

    if user is not None:
        auth.login(request, user)
        token = Token.objects.get_or_create(user=user)[0]

        if user.is_active is False:
            send_activation_email(user)

        return Response({
            "username": user.username,
            "Authorization": "Token",
            "access_token": token.key,
            "Activation": user.is_active
        }, status=status.HTTP_200_OK)

    else:
        return Response(status=status.HTTP_401_UNAUTHORIZED)


@api_view(["POST"])
@permission_classes([AllowAny])
def register(request: Request) -> Response:
    if valid_username(request.data["username"]) == False:
        return Response({
            "message": "Username invalid or already taken"
        }, status=status.HTTP_417_EXPECTATION_FAILED)
    user = create_user(
        request.data["username"], request.data["email"], password=request.data["password"])
    auth.login(request, user)
    token = Token.objects.get_or_create(user=user)[0]

    return Response({
        "username": user.username,
        "Authorization": "Token",
        "access_token": token.key,
        "Activation": user.is_active
    }, status=status.HTTP_201_CREATED)


@api_view(["POST"])
def activate(request: Request) -> Response:
    activation_code = request.data["code"]

    request.user.is_active = True

    return Response(status=status.HTTP_200_OK)

@api_view(["GET"])
@permission_classes([AllowAny])
def request_token(request: Request) -> Response:
    token_hash = request.META["Authorization"].split(' ')[-1]

    for token in Token.objects.all():
        hasher = hashlib.sha3_256()
        hasher.update(bytes(token.key, "utf-8"))
        if token_hash == hasher.hexdigest():
            user = token.user
            return Response({
                "username": user.username,
                "Authorization": "Token",
                "access_token": token.key,
                "Activation": user.is_active
            }, status=status.HTTP_200_OK)

    return Response({
        "message": "Invalid token hash"
    }, status=status.HTTP_401_UNAUTHORIZED)



@api_view(["GET"])
def logout(request: Request) -> Response:
    auth.logout(request)
    request.user.auth_token.delete()

    return Response(status=status.HTTP_200_OK)


@api_view(["POST"])
def update(request: Request) -> Response:
    if request.data["username"] != None and valid_username(request.data["username"]):
        request.user.username = request.data["username"]
    if request.data["password"] != None and check_password(request.data["old_password"], request.user.password):
        request.user.set_password(request.data["password"])
    if request.data["email"] != None:
        request.user.email = request.data["email"]

    return Response({
        "username": request.user.username,
        "password_changed": check_password(request.data["password"], request.user.password),
        "email": request.user.email
    }, status=status.HTTP_200_OK)


@api_view(["GET"])
def link(request: Request) -> Response:
    token_hash = request.GET["state"]

    for token in Token.objects.all():
        hasher = hashlib.sha3_256()
        hasher.update(bytes(token.key, "utf-8"))
        if token_hash == hasher.hexdigest():
            code = request.GET["code"]
            user = token.user
            discord_integration = DiscordIntegration()
            discord_integration.create(code, "link")

            for emblify_user in EmblifyUser.objects.all():
                if emblify_user.discord_integration.user_id == discord_integration.user_id:
                    return Response({
                        "message": "Discord account is already linked to another emblify account"
                    }, status=status.HTTP_401_UNAUTHORIZED)

            discord_integration.save()
            emblify_user = EmblifyUser.objects.get(user=user)
            emblify_user.discord_integration = discord_integration

            return Response({
                "message": "Discord account successfully linked to emblify account: " + user.username
            }, status=status.HTTP_200_OK)

    return Response({
        "message": "Invalid token hash"
    }, status=status.HTTP_401_UNAUTHORIZED)


@api_view(["GET"])
def unlink(request: Request) -> Response:
    emblify_user = EmblifyUser.objects.get(user=request.user)
    emblify_user.discord_integration.delete()

    return Response({
        "message": "Discord account successfully unlinked"
    }, status=status.HTTP_200_OK)


@api_view(["DELETE"])
def close(request: Request) -> Response:
    request.user.is_active = False
    emblify_user = EmblifyUser.objects.get(user=request.user)
    emblify_user.is_private = True

    return Response({
        "message": "emblify account successfully closed"
    }, status=status.HTTP_200_OK)

# Helper Functions


def get_user_from_username(username: str) -> User:
    for user in User.objects.all():
        if user.username == username:
            return user
    return None


def get_user_from_discord(discord_integration: DiscordIntegration) -> User:
    for emblify_user in EmblifyUser.objects.all():
        if emblify_user.discord_integration.equals(discord_integration):
            return emblify_user.user

    discord_integration.save()
    return create_user(
        username=discord_integration.user_name,
        email=discord_integration.user_email,
        discord_integration=discord_integration)


def create_user(username: str, email: str, password: str = None, discord_integration: DiscordIntegration = None) -> User:
    if valid_username(username) == False:
        username = "emblify_" + get_random_string(5)

    user = User.objects.create_user(
        username=username, email=email, password=password)
    EmblifyUser.objects.create(
        user=user, discord_integration=discord_integration)
    user.is_active = False
    send_activation_email(user)

    return user


def send_activation_email(user: User):
    user.is_active = True


def valid_username(username: str):
    if username in CUSTOM_URLS:
        return False

    for user in User.objects.all():
        if user.username == username:
            return False

    return True
