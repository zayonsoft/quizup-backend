from quizapp.serializers import QuestionSerializer
from rest_framework.views import APIView, Response, status
from quizapp.models import Question, UserMailValidator
from quizapp.generator import generate_code, verify_code
from quizapp.registration_mails import send_validation_code, send_success_reg
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework.request import Request

DEBUG = settings.DEBUG
User = get_user_model()


class QuestionView(APIView):
    def get(self, request: Request):
        questions = Question.objects.all()
        # This will be for all questions for a person
        serializer = QuestionSerializer(questions, many=True)
        return Response({"data": serializer.data}, status=status.HTTP_200_OK)

    def post(self, request: Request):
        # Will have to make sure the person making the request created the contest
        contest = request.data.get("contest")
        level = request.data.get("level")
        is_chosen = request.data.get("is_choden")
        has_option = request.data.get("has_option")

        serializer = QuestionSerializer(data=request.data)
        if serializer.is_valid():
            return Response(status=status.HTTP_200_OK)

        return Response(
            {"detail": serializer.errors}, status=status.HTTP_501_NOT_IMPLEMENTED
        )


class MailValidationView(APIView):
    def post(self, request):
        email: str = request.data.get("email")

        empty_values = {}
        if not (email and email.strip()):
            empty_values["email"] = ["This field is required"]

        if len(empty_values) != 0:
            return Response(
                {"detail": empty_values}, status=status.HTTP_400_BAD_REQUEST
            )

        # Checking if a user already exists with the email
        # so that the person won't bother wasting my time
        if (
            User.objects.filter(email__iexact=email).exists()
            or User.objects.filter(username=email).exists()
        ):
            return Response(
                {
                    "detail": "Cannot generate a code for an existing user e-mail, try a different e-mail"
                },
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )

        code_expires_in = 15
        code = generate_code(email, expires_in_minutes=code_expires_in, length=6)
        formated_code = " ".join(code[i : i + 3] for i in range(0, len(code), 3))

        is_sent = send_validation_code(
            email, formated_code, code_expires_in, is_testing=DEBUG
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


"""
✅ The View First Checks if the email has a generated code and only proceeds when that is checked
✅ Validity of the code is  checked
✅ Checks if entries don't match an existing username
✅ Checks if entries don't match an existing email
✅ Then account can be created
✅ delete the validation code instance from the database
✅ Test the API endpoint
"""


class UserSignupView(APIView):
    def post(self, request: Request):
        username: str = request.data.get("username")
        email: str = request.data.get("email")
        password: str = request.data.get("password")
        validation_code: str = request.data.get("validation_code")

        empty_values = {}  # dictionary to append the empty values
        if not (username and username.strip()):
            empty_values["username"] = ["This field is required."]
        if not (email and email.strip()):
            empty_values["email"] = ["This field is required."]
        if not (password and password.strip()):
            empty_values["password"] = ["This field is required."]
        if not (validation_code and validation_code.strip()):
            empty_values["validation_code"] = ["This field is required."]

        # Check if there are empty values, display the list
        if len(empty_values) != 0:
            return Response(
                {"detail": empty_values},
                status=status.HTTP_400_BAD_REQUEST,
            )
        username = username.strip()
        email = email.strip()
        password = password.strip()

        if not UserMailValidator.objects.filter(email__iexact=email).exists():
            return Response({"detail": "The Email Has no generated code"})

        is_code_valid = verify_code(email, validation_code)

        if not is_code_valid:
            return Response(
                {"detail": "Code is invalid or expired, you can request a new one"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check for existing Username with the entered Username and Email
        # if it does, then send the user back to where they're coming from
        if (
            User.objects.filter(username=username).exists()
            or User.objects.filter(username=email).exists()
        ):
            return Response(
                {"detail": "Username must be unique for each user"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )
        # checking if an email matches the username or email the user is trying to use
        if (
            User.objects.filter(email=username).exists()
            or User.objects.filter(email=email).exists()
        ):
            return Response(
                {"detail": "Email must be unique, try a different e-mail"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )

        created_user = User.objects.create_user(
            username=username, email=email, password=password
        )

        validator = UserMailValidator.objects.get(email=created_user.email)
        validator.delete()

        return Response(
            {"detail": f"User created successfully"},
            status=status.HTTP_201_CREATED,
        )


def confirmUserDetail(email_or_username):
    if (
        User.objects.filter(username=email_or_username).exists()
        or User.objects.filter(email=email_or_username).exists()
    ):
        return True
    else:
        return False


class SigninView(APIView):
    def post(self, request: Request):
        username_or_email: str = request.data.get("username_or_email")
        password: str = request.data.get("password")

        empty_values = {}
        if not (username_or_email and username_or_email.strip()):
            empty_values["username_or_email"] = ["This field is required"]

        if not (password and password.strip()):
            empty_values["password"] = ["This field is required"]

        if len(empty_values) != 0:
            return Response(
                {"detail": empty_values}, status=status.HTTP_400_BAD_REQUEST
            )

        password = password.strip()
        username_or_email = username_or_email.strip()
        username = ""

        if not confirmUserDetail(username_or_email):
            return Response(
                {"detail": "Invalid Username or Email"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if User.objects.filter(username=username_or_email).exists():
            username = username_or_email

        else:
            username = User.objects.get(email=username_or_email).username

        user = authenticate(username=username, password=password)

        if user is not None:
            obtained_tokens = RefreshToken.for_user(user)
            return Response(
                {
                    "tokens": {
                        "access": str(obtained_tokens.access_token),
                        "refresh": str(obtained_tokens),
                    },
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"detail": "Invalid Login Credentials"},
                status=status.HTTP_400_BAD_REQUEST,
            )
