from django.contrib import auth
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.authtoken.models import Token
from users.models import EmblifyUser, DiscordIntegration


# Create your views here.
CUSTOM_URLS = ["oauth", "login", "register", "activate", "exchange",
               "logout", "update", "unlink", "close", "@me"]

# API Views


@api_view(["GET"])
def read(request: Request, username: str) -> Response:
    user = None
    if username == "@me":
        user = request.user
    else:
        user = User.objects.get(username=username)
    emblify_user = EmblifyUser.objects.get(user=user)
    user_info = {
        "username": user.username,
        "is_private": emblify_user.is_private
    }

    if request.user.username == username or emblify_user.is_private is False:
        if emblify_user.discord_integration is not None:
            user_info["discord_id"] = emblify_user.discord_integration.user_id

    return Response(user_info, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([AllowAny])
def oauth(request: Request) -> Response:
    discord_integration = DiscordIntegration()
    refresh_token = discord_integration.create(
        request.data["code"], request.data["platform"])
    user = get_user_from_discord(discord_integration)

    if user is None:
        if request.user.is_authenticated:  # Link discord account to existing account
            user = request.user
            discord_integration.save()
            emblify_user = EmblifyUser.objects.get(user=user)
            emblify_user.discord_integration = discord_integration
            emblify_user.save()
        else:  # Return a discord refresh token to accept when creating a new user
            return Response({
                "discord_token": refresh_token
            }, status=status.HTTP_400_BAD_REQUEST)

    token = Token.objects.get_or_create(user=user)[0]

    return Response({
        "username": user.username,
        "access_token": token.key,
        "active": user.is_active,
        "discord_id": discord_integration.user_id
    }, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([AllowAny])
def login(request: Request) -> Response:
    user = auth.authenticate(
        request, username=request.data["username"], password=request.data["password"])

    if user is not None:
        token = Token.objects.get_or_create(user=user)[0]

        if user.is_active is False:
            send_activation_email(user)

        return Response({
            "username": user.username,
            "access_token": token.key,
            "Active": user.is_active
        }, status=status.HTTP_200_OK)

    return Response(status=status.HTTP_401_UNAUTHORIZED)


@api_view(["POST"])
@permission_classes([AllowAny])
def register(request: Request) -> Response:
    if valid_username(request.data["username"]) == False:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    user = create_user(
        request.data["username"], request.data["email"], password=request.data["password"])
    emblify_user = EmblifyUser.objects.get(user=user)
    token = Token.objects.create(user=user)

    if "discord_token" in request.data:
        discord_integration = DiscordIntegration()
        discord_integration.create_from_token(request.data["discord_token"])
        if get_user_from_discord(discord_integration) is None:
            discord_integration.save()
            emblify_user.discord_integration = discord_integration
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)

    user.save()
    emblify_user.save()

    return Response({
        "username": user.username,
        "access_token": token.key,
        "Active": user.is_active
    }, status=status.HTTP_201_CREATED)


@api_view(["POST"])
def activate(request: Request) -> Response:
    activation_code = request.data["activation_code"]

    request.user.is_active = True

    request.user.save()

    return Response(status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([AllowAny])
def exchange(request: Request) -> Response:
    if request.data["type"] == "token":
        return Response({
            "hash": token_to_hash(request.data["token"])
        }, status=status.HTTP_400_BAD_REQUEST)
    elif request.data["type"] == "hash":
        return Response({
            "token": hash_to_token(request.data["username"], request.data["hash"])
        })
    return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
def logout(request: Request) -> Response:
    request.user.auth_token.delete()

    return Response(status=status.HTTP_200_OK)


@api_view(["POST"])
def update(request: Request) -> Response:
    password_changed = False
    if request.data["username"] != None and valid_username(request.data["username"]):
        request.user.username = request.data["username"]
    if request.data["password"] != None and check_password(request.data["old_password"], request.user.password):
        request.user.set_password(request.data["password"])
        password_changed = True
    if request.data["email"] != None:
        request.user.email = request.data["email"]

    request.user.save()

    return Response({
        "username": request.user.username,
        "password_changed": password_changed,
        "email": request.user.email
    }, status=status.HTTP_200_OK)


@api_view(["DELETE"])
def unlink(request: Request) -> Response:
    emblify_user = EmblifyUser.objects.get(user=request.user)
    emblify_user.discord_integration.delete()

    return Response(status=status.HTTP_200_OK)


@api_view(["DELETE"])
def close(request: Request) -> Response:
    request.user.is_active = False
    emblify_user = EmblifyUser.objects.get(user=request.user)
    emblify_user.is_private = True

    request.user.save()
    emblify_user.save()

    return Response(status=status.HTTP_200_OK)

# Helper Functions


def get_user_from_discord(discord_integration: DiscordIntegration) -> User:
    for emblify_user in EmblifyUser.objects.all():
        if discord_integration.equals(emblify_user.discord_integration):
            return emblify_user.user


def create_user(username: str, email: str, password: str = None, discord_integration: DiscordIntegration = None) -> User:
    user = User.objects.create_user(
        username=username, email=email, password=password)
    EmblifyUser.objects.create(
        user=user, discord_integration=discord_integration)
    user.is_active = False
    send_activation_email(user)
    user.save()

    return user


def send_activation_email(user: User) -> None:
    user.is_active = True
    user.save()


def valid_username(username: str) -> bool:
    if username in CUSTOM_URLS:
        return False

    for user in User.objects.all():
        if user.username == username:
            return False

    return True


def token_to_hash(token: str) -> str:
    token_hash = make_password(token).split('$')
    return "{}${}".format(token_hash[-2], token_hash[-1])


def hash_to_token(username: str, token_hash: str) -> str:
    user = User.objects.get(username=username)
    token = Token.objects.get(user=user)

    if check_password(token, "pbkdf2_sha256$320000${}".format(token_hash)):
        return token.key
