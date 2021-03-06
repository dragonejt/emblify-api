from django.urls import path
from users import views

urlpatterns = [
    path("oauth", views.oauth),
    path("login", views.login),
    path("register", views.register),
    path("activate", views.activate),
    path("exchange", views.exchange),
    path("logout", views.logout),
    path("update", views.update),
    path("unlink", views.unlink),
    path("close", views.close),
    path("<str:username>", views.read),

]
