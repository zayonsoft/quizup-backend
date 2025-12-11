from quizapp.serializers import (
    QuestionSerializer,
    ContestSerializer,
    ContestantSerializer,
)
from rest_framework.views import APIView, Response, status
from quizapp.models import Question, UserMailValidator, Contest, Contestant, Option
from quizapp.generator import generate_code, verify_code
from quizapp.registration_mails import send_validation_code
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework.request import Request
from rest_framework.permissions import IsAuthenticated
import uuid, json
from django.db.models import Q


DEBUG = settings.DEBUG
User = get_user_model()


class MailValidationView(APIView):
    def post(self, request):
        email: str = request.data.get("email")

        empty_values = {}
        if not (email and email.strip()):
            empty_values["email"] = ["This field is required"]

        if len(empty_values) != 0:
            return Response(empty_values, status=status.HTTP_400_BAD_REQUEST)

        # Checking if a user already exists with the email
        # so that the person won't bother wasting my time
        if (
            User.objects.filter(email__iexact=email).exists()
            or User.objects.filter(username=email).exists()
        ):
            return Response(
                {
                    "email": [
                        "Cannot generate a code for an existing user e-mail, try a different e-mail"
                    ]
                },
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )

        code_expires_in = 15
        code = generate_code(email, expires_in_minutes=code_expires_in, length=6)
        formated_code = " ".join(code[i] for i in range(0, len(code)))

        is_sent = send_validation_code(
            email, formated_code, code_expires_in, is_testing=DEBUG
        )
        if is_sent:
            return Response(
                {"detail": f"Code Sent to '{email}'"}, status=status.HTTP_200_OK
            )
        else:
            return Response(
                {
                    "non_field_errors": [
                        f"Couldn't Send Mail to {email}, pls try again later"
                    ]
                },
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
            return Response({"detail": {"email": ["The Email Has no generated code"]}})

        is_code_valid = verify_code(email, validation_code)

        if not is_code_valid:
            return Response(
                {
                    "detail": {
                        "code": [
                            "Code is invalid or expired, you can request a new one"
                        ]
                    }
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check for existing Username with the entered Username and Email
        # if it does, then send the user back to where they're coming from
        if (
            User.objects.filter(username=username).exists()
            or User.objects.filter(username=email).exists()
        ):
            return Response(
                {"detail": {"username": ["Username must be unique for each user"]}},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )
        # checking if an email matches the username or email the user is trying to use
        if (
            User.objects.filter(email=username).exists()
            or User.objects.filter(email=email).exists()
        ):
            return Response(
                {"detail": {"email": ["Email must be unique, try a different e-mail"]}},
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
        username: str

        if not confirmUserDetail(username_or_email):
            return Response(
                {"detail": {"username_or_email": ["Invalid Username or Email"]}},
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
                {"detail": {"non_field_errors": ["Invalid Login Credentials"]}},
                status=status.HTTP_400_BAD_REQUEST,
            )


# For GetAll (search included), Create New Contest
class ContestsView(APIView):
    permission_classes = [IsAuthenticated]

    # create contest
    def post(self, request: Request):
        name: str = request.data.get("name")
        levels: str = request.data.get("levels")

        empty_values = {}

        if not (name and name.strip()):
            empty_values["name"] = ["This field is required"]
        if not (levels and levels.strip()):
            empty_values["levels"] = ["This field is required"]

        if len(empty_values) != 0:
            return Response(
                {"detail": empty_values}, status=status.HTTP_400_BAD_REQUEST
            )

        if Contest.objects.filter(name__iexact=name, created_by=request.user):
            return Response(
                {"detail": {"name": ["A Contest with this name already exists"]}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not levels.isdigit():
            return Response(
                {"detail": {"levels": ["Must be a number"]}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        Contest.objects.create(name=name, levels=levels, created_by=request.user)

        return Response(
            {"detail": "Contest created successfully"}, status=status.HTTP_201_CREATED
        )

    # get all the user's contest
    def get(self, request: Request):
        search = request.query_params.get("search")
        contests: Contest
        if search and search.strip():
            contests = Contest.objects.filter(created_by=request.user).filter(
                Q(name__icontains=search) | Q(code__icontains=search)
            )
        else:
            contests = Contest.objects.filter(created_by=request.user)
        serializer = ContestSerializer(contests, many=True)
        return Response({"detail": serializer.data}, status=status.HTTP_200_OK)


# For GET, EDIT, DELETE requires pk parameter
class ContestView(APIView):
    permission_classes = [IsAuthenticated]

    # fetch a specific contest
    def get(self, request: Request, pk):
        try:
            uuid.UUID(pk)
        except:
            return Response(
                {"detail": "Invalid Id"}, status=status.HTTP_400_BAD_REQUEST
            )
        if not Contest.objects.filter(id=pk, created_by=request.user).exists():
            return Response({"detail": "Not Found"}, status=status.HTTP_404_NOT_FOUND)
        contest = Contest.objects.get(pk=pk)

        serializer = ContestSerializer(contest)
        return Response({"detail": serializer.data}, status=status.HTTP_200_OK)

    def delete(self, request: Request, pk):
        try:
            uuid.UUID(pk)
        except:
            return Response(
                {"detail": "Invalid Id"}, status=status.HTTP_400_BAD_REQUEST
            )

        if not Contest.objects.filter(id=pk, created_by=request.user).exists():
            return Response({"detail": "Not Found"}, status=status.HTTP_404_NOT_FOUND)
        contest = Contest.objects.get(pk=pk)

        contest.delete()
        return Response(
            {"detail": "Contest Deleted"}, status=status.HTTP_204_NO_CONTENT
        )

    def patch(self, request: Request, pk):
        try:
            uuid.UUID(pk)
        except:
            return Response(
                {"detail": "Invalid Id"}, status=status.HTTP_400_BAD_REQUEST
            )

        if not Contest.objects.filter(id=pk, created_by=request.user).exists():
            return Response({"detail": "Not Found"}, status=status.HTTP_404_NOT_FOUND)
        contest = Contest.objects.get(pk=pk)

        name: str = request.data.get("name")

        if Contest.objects.filter(name__icontains=name).exclude(pk=pk).exists():
            return Response(
                {"detail": {"name": ["A Contest with this name already exists"]}},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = ContestSerializer(contest, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"detail": "Contest Updated"}, status=status.HTTP_200_OK)
        else:
            return Response(
                {"detail": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
            )


class ContestantsView(APIView):
    permission_classes = [IsAuthenticated]

    # Creating Contestant
    def post(self, request: Request, contest_id: str):

        try:
            uuid.UUID(contest_id)
        except:
            return Response(
                {"detail": "Invalid Contest Id"}, status=status.HTTP_400_BAD_REQUEST
            )

        if not Contest.objects.filter(pk=contest_id, created_by=request.user):
            return Response(
                {
                    "detail": "Contest not found or does not belong to the authenticated user"
                }
            )

        serializer = ContestantSerializer(
            data=request.data, context={"request": request, "contest_id": contest_id}
        )
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"detail": "Contestant Created"}, status=status.HTTP_201_CREATED
            )
        else:
            return Response(
                {"detail": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
            )

    # get all user's contestants for a contest
    def get(self, request: Request, contest_id: str):
        try:
            uuid.UUID(contest_id)
        except:
            return Response(
                {"detail": "Invalid Contest Id"}, status=status.HTTP_400_BAD_REQUEST
            )
        if not Contest.objects.filter(pk=contest_id, created_by=request.user).exists():
            return Response(
                {
                    "detail": "Contest not found or does not belong to the authenticated user"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        contest = Contest.objects.prefetch_related("contestant_set").get(
            pk=contest_id, created_by=request.user
        )
        search: str = request.query_params.get("search")
        contestants: Contestant
        if not (search and search.strip()):
            contestants = contest.contestant_set.all()

        else:
            search = search.strip()
            contestants = contest.contestant_set.all().filter(
                Q(name__icontains=search) | Q(contest__name__icontains=search)
            )

        serializer = ContestantSerializer(contestants, many=True)

        return Response({"detail": serializer.data}, status=status.HTTP_200_OK)


def check_uuid(id: str):
    try:
        uuid.UUID(id)
        return True
    except:
        return False


# to cater for delete, edit, update, fetching a specific contestant
class ContestantView(APIView):
    def get(self, request: Request, contestant_id: str):
        if not check_uuid(contestant_id):
            return Response(
                {"detail": "Invalid Contestant Id"}, status=status.HTTP_400_BAD_REQUEST
            )

        if not Contestant.objects.filter(
            pk=contestant_id, contest__created_by=request.user
        ).exists():
            return Response(
                {
                    "detail": "Contestant not found or does not belong to the authenticated user"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        contestant: Contestant

        contestant = Contestant.objects.select_related("contest").get(
            pk=contestant_id, contest__created_by=request.user
        )
        serializer = ContestantSerializer(contestant)

        return Response({"detail": serializer.data}, status=status.HTTP_200_OK)

    def patch(self, request: Request, contestant_id: str):

        if not check_uuid(contestant_id):
            return Response(
                {"detail": "Invalid Contestant Id"}, status=status.HTTP_400_BAD_REQUEST
            )

        if not Contestant.objects.filter(
            pk=contestant_id, contest__created_by=request.user
        ).exists():
            return Response(
                {
                    "detail": "Contestant not found or does not belong to the authenticated user"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        contestant = Contestant.objects.get(
            pk=contestant_id, contest__created_by=request.user
        )
        serializer = ContestantSerializer(
            contestant,
            data=request.data,
            context={"contest_id": contestant.contest.pk},
            partial=True,
        )
        if serializer.is_valid():
            serializer.save()
            return Response({"detail": "Contestant Updated"}, status=status.HTTP_200_OK)
        else:
            return Response(
                {"detail": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
            )

    def delete(self, request: Request, contestant_id: str):
        if not check_uuid(contestant_id):
            return Response(
                {"detail": "Invalid Contestant Id"}, status=status.HTTP_400_BAD_REQUEST
            )

        if not Contestant.objects.filter(
            pk=contestant_id, contest__created_by=request.user
        ).exists():
            return Response(
                {
                    "detail": "Contestant not found or does not belong to the authenticated user"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        contestant = Contestant.objects.get(
            pk=contestant_id, contest__created_by=request.user
        )
        contestant.delete()
        return Response({"detail": "Successfully Deleted"}, status=status.HTTP_200_OK)


def check_options(options: str):
    options = str(options).replace(
        "'", '"'
    )  # to prevent the error I encountered doing json.loads()
    try:
        options: list[dict[str, any]] = json.loads(options)
        if not type(options) == list:
            return False
        for option in options:
            text: str = option.get("text")
            if not (text and type(text) == str and text.strip()):
                return False
            is_correct: bool = option.get("is_correct")
            is_correct = get_boolean_value(is_correct)
            print(is_correct)
            if not type(is_correct) == bool:
                return False
        return True
    except:
        return False


def check_options_truth(options: list[dict[str, any]]):
    true_option_count = 0
    for option in options:
        is_correct = option.get("is_correct")
        if get_boolean_value(is_correct) == True:
            true_option_count += 1

    if true_option_count > 1:
        return False
    else:
        return True


def get_boolean_value(value: str):
    boolean_value = {
        "TRUE": True,
        "1": True,
        True: True,
        "FALSE": False,
        "0": False,
        False: False,
    }
    return boolean_value.get(str(value).upper())


class QuestionView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request: Request, contest_id: str):
        questions = (
            Question.objects.select_related("contest")
            .prefetch_related("options")
            .filter(contest__created_by=request.user)
        )
        # This will be for all questions for a person
        serializer = QuestionSerializer(questions, many=True)
        return Response({"data": serializer.data}, status=status.HTTP_200_OK)

    # creating questions for a specific contest
    def post(self, request: Request, contest_id: str):
        # Will have to make sure the person making the request created the contest
        if not check_uuid(contest_id):
            return Response(
                {"detail": "Invalid Contest Id"}, status=status.HTTP_400_BAD_REQUEST
            )
        if not Contest.objects.filter(pk=contest_id, created_by=request.user).exists():
            return Response(
                {
                    "detail": "Contest not found or does not belong to the authenticated user"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        contest = Contest.objects.get(pk=contest_id, created_by=request.user)
        text: str = request.data.get("text")
        level: str = str(request.data.get("level"))
        has_option: bool = request.data.get("has_option")
        options: list = request.data.get("options")
        error_values = {}
        if not (level and level.isdigit()):
            error_values["level"] = ["This field is required and Must be a Number"]
        if not (text and text.strip()):
            error_values["text"] = ["This field is required"]

        has_option = get_boolean_value(has_option)
        # Validating different types of boolean requests
        if not (has_option):
            error_values["has_options"] = ["Should be either 'true' or 'false'"]
        if has_option and not (type(options) == list):
            error_values["options"] = ["Options should be of list type '[]'"]

        options_are_valid = check_options(options)
        if options_are_valid:
            options = str(options).replace("'", '"')
            options: list = json.loads(str(options))
        else:
            error_values["options"] = ["Should be a valid list of option objects"]

        if has_option and options_are_valid and not len(options) > 1:
            error_values["options"] = [
                "Options must be more than one when options are set"
            ]

        if len(error_values) != 0:
            return Response(
                {"detail": error_values}, status=status.HTTP_400_BAD_REQUEST
            )
        if not check_options_truth(options):
            return Response(
                {"detail": {"option": ["Only one of the options can be true"]}},
                status=status.HTTP_400_BAD_REQUEST,
            )
        text = text.strip()
        level = int(level)
        if level > contest.levels:
            return Response(
                {
                    "level": [
                        f"You can only set questions for {"level 1" if not contest.levels>1 else f"level 1 - {contest.levels}"}"
                    ]
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        question = Question.objects.create(
            contest=contest, text=text, level=level, has_option=has_option
        )

        Option.objects.bulk_create(
            [
                Option(
                    question=question, text=option.text, is_correct=option.is_correct
                )
                for option in options
            ]
        )
        return Response(
            {"detail": "Question Added Successfully"}, status=status.HTTP_200_OK
        )
