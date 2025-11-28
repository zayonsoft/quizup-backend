from rest_framework import serializers
from quizapp.models import Question
from django.contrib.auth import get_user_model

User = get_user_model()


class QuestionSerializer(serializers.ModelSerializer):

    class Meta:
        model = Question
        fields = "__all__"


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ["username", "email", "first_name", "last_name"]
