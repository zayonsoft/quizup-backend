from rest_framework import serializers
from quizapp.models import Question


class QuestionSerializer(serializers.ModelSerializer):

    class Meta:
        model = Question
        fields = "__all__"
