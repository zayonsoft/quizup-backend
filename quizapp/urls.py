from django.urls import path
from quizapp import views

urlpatterns = [
    path("questions", views.QuestionView.as_view(), name="questions"),
    path("validate_mail", views.UserValidationCode.as_view(), name="validate_mail"),
]
