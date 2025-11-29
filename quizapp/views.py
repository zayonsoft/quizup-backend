from quizapp.serializers import QuestionSerializer
from rest_framework.views import APIView, Response, status
from quizapp.models import Question
from quizapp.generator import generate_code
from quizapp.registration_mails import send_validation_code


class QuestionView(APIView):
    def get(self, request):
        questions = Question.objects.all()
        # This will be for all questions for a person
        serializer = QuestionSerializer(questions, many=True)
        return Response({"data": serializer.data}, status=status.HTTP_200_OK)

    def post(self, request):
        # Will have to make sure the person making the request created the contest
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


class UserValidationCode(APIView):
    def post(self, request):
        email = request.data.get("email")

        code_expires_in = 15

        code = generate_code(email, expires_in_minutes=code_expires_in, length=6)
        formated_code = " ".join(code[i : i + 3] for i in range(0, len(code), 3))

        is_sent = send_validation_code(
            email, formated_code, code_expires_in, is_testing=True
        )
        if is_sent:
            return Response(
                {"detail": f"Code Sent to '{email}'"}, status=status.HTTP_200_OK
            )
        else:
            return Response(
                {"detail": f"Couldn't Send Mail to {email}, pls try again later"},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class UserSignup(APIView):
    def post(self, request):
        username = request.data.get("username")
        email = request.data.get("email")
        password = request.data.get("password")
        validation_code = request.data.get("validation_code")
