from rest_framework import serializers
from quizapp.models import Question, Contest, Contestant, Option
from django.contrib.auth import get_user_model
from rest_framework.validators import UniqueTogetherValidator

User = get_user_model()


class QuestionSerializer(serializers.ModelSerializer):

    class Meta:
        model = Question
        fields = "__all__"


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ["username", "email", "first_name", "last_name"]


class ContestSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    date_created = serializers.DateTimeField(
        format="%d-%b-%y, %I:%M %p", read_only=True
    )
    code = serializers.CharField(read_only=True)
    created_by = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Contest
        fields = "__all__"

    validators = [
        UniqueTogetherValidator(
            queryset=Contest.objects.all(),
            fields=["name", "created_by"],
            message="User has a contest with the given name",
        )
    ]
