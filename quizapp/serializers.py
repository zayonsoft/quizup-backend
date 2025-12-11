from rest_framework import serializers
from quizapp.models import Question, Contest, Contestant, Option
from django.contrib.auth import get_user_model
from rest_framework.validators import UniqueTogetherValidator, DataError
import uuid
from rest_framework.request import Request

User = get_user_model()


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


class ContestantSerializer(serializers.ModelSerializer):
    contest = ContestSerializer(read_only=True)

    class Meta:
        model = Contestant
        fields = "__all__"

    def validate_name(self, value: str):
        value = value.strip()
        if not (value and value.strip()):
            raise serializers.ValidationError("This field is required")

        return value

    def validate(self, attrs: dict):
        name = attrs.get("name")
        if not name:
            raise serializers.ValidationError({"name": "This Field is required"})
        contest_id = self.context.get("contest_id")
        contest = Contest.objects.get(pk=contest_id)
        if not self.instance:
            if Contestant.objects.filter(name__iexact=name, contest=contest).exists():
                raise serializers.ValidationError(
                    {"name": "Contestant name must be unique in a contest"}
                )
        else:
            if (
                Contestant.objects.filter(name__iexact=name, contest=contest)
                .exclude(pk=self.instance.pk)
                .exists()
            ):
                raise serializers.ValidationError(
                    {"name": "Contestant name must be unique in a contest"}
                )
        return attrs

    def create(self, validated_data: dict):
        contest_id = self.context.get("contest_id")
        contest = Contest.objects.get(pk=contest_id)
        validated_data["contest"] = contest

        return super().create(validated_data)


class OptionSerializer(serializers.ModelSerializer):

    class Meta:
        model = Option
        fields = "__all__"


class QuestionSerializer(serializers.ModelSerializer):
    option = OptionSerializer(many=True, source="option_set")
    contest = ContestSerializer(read_only=True)
    time_added = serializers.DateTimeField(format="%d-%b-%y, %I:%M %p", read_only=True)
    time_edited = serializers.DateTimeField(format="%d-%b-%y, %I:%M %p", read_only=True)

    class Meta:
        model = Question
        fields = "__all__"
