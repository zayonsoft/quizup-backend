from quizapp.serializers import QuestionSerializer
from rest_framework.views import APIView, Response, status
from quizapp.models import Question


class QuestionView(APIView):
    def get(self, request):
        questions = Question.objects.all()
        # This will be for all questions for a person
        serializer = QuestionSerializer(questions, many=True)
        return Response({"data": serializer.data}, status=status.HTTP_200_OK)

    def post(self, request):
        contest = request.data.get("contest")
        level = request.data.get("level")
        is_chosen = request.data.get("is_choden")
        has_option = request.data.get("has_option")

        serializer = QuestionSerializer(data=request.data)
        if serializer.is_valid():
            return Response(status=status.HTTP_200_OK)

        return Response(
            {"errors": serializer.errors}, status=status.HTTP_501_NOT_IMPLEMENTED
        )
