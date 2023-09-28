from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("l1", views.l1, name="l1"),
    path("l2", views.l2, name="l2"),
]