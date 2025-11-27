from quizapp.serializers import QuestionSerializer
from rest_framework.views import APIView
from quizapp.models import Question


class QuestionView(APIView):
    def get(self, request):
        questions = Question.objects.all()