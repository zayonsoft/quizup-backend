from django.urls import path
from quizapp import views
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path("validate_mail", views.MailValidationView.as_view(), name="validate_mail"),
    path("email_validator", views.MailValidationView.as_view(), name="email_validator"),
    path("user_signup", views.UserSignupView.as_view(), name="user_signup"),
    path("signup", views.UserSignupView.as_view(), name="signup"),
    path("user_signin", views.SigninView.as_view(), name="user_signin"),
    path("signin", views.SigninView.as_view(), name="signin"),
    path("refresh_token", TokenRefreshView.as_view(), name="refresh_token"),
    path("contests", views.ContestsView.as_view(), name="contests"),
    path("contest/<str:pk>", views.ContestView.as_view(), name="contest"),
    path(
        "contestants/<str:contest_id>", views.ContestantsView.as_view(), name="contest"
    ),
    path(
        "contestant/<str:contestant_id>",
        views.ContestantView.as_view(),
        name="contestant",
    ),
    path("questions/getAll", views.AllQuestionsView.as_view(), name="all_questions"),
    path("questions/<str:contest_id>", views.QuestionsView.as_view(), name="questions"),
    path("question/<str:question_id>", views.QuestionView.as_view(), name="question"),
    path(
        "contestControl/randomQuestion/<str:contest_id>",
        views.RandomQuestionSelection.as_view(),
        name="random_question",
    ),
    path(
        "contestControl/resetContest/<str:contest_id>",
        views.ResetContestView.as_view(),
        name="random_question",
    ),
    path(
        "contestControl/<str:contest_id>/displaySpecificQuestion",
        views.DisplaySpecificQuestionView.as_view(),
        name="random_question",
    ),
    path(
        "view/<str:contest_id>/currentQuestion",
        views.GeneralQuestionView.as_view(),
        name="viewer_current_question",
    ),
]
