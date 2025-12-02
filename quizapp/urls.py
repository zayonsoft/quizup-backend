from django.urls import path
from quizapp import views
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path("questions", views.QuestionView.as_view(), name="questions"),
    path("validate_mail", views.UserValidationCode.as_view(), name="validate_mail"),
    path("user_signup", views.UserSignup.as_view(), name="user_signup"),
    path("refresh_token", TokenRefreshView.as_view(), name="refresh_token"),
]
