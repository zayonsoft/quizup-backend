from django.urls import path
from quizapp import views

urlpatterns = [path("questions", views.QuestionView.as_view(), name="questions")]
