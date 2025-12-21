from quizapp.serializers import (
    QuestionSerializer,
    ContestSerializer,
    ContestantSerializer,
    ContestControlSerializer,
)
from rest_framework.views import APIView, Response, status
from quizapp.models import (
    Question,
    UserMailValidator,
    Contest,
    Contestant,
    Option,
    ContestControl,
)
from quizapp.generator import generate_code, verify_code
from quizapp.registration_mails import send_validation_code
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework.request import Request
from rest_framework.permissions import IsAuthenticated
import uuid, json, random
from django.db.models import Q, Prefetch
from django.db.models.query import QuerySet
from django.db.models.manager import BaseManager


DEBUG = settings.DEBUG
User = get_user_model()


def check_uuid(id: str):
    try:
        uuid.UUID(id)
        return True
    except:
        return False


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
                empty_values,
                status=status.HTTP_400_BAD_REQUEST,
            )
        username = username.strip()
        email = email.strip()
        password = password.strip()

        if not UserMailValidator.objects.filter(email__iexact=email).exists():
            return Response(
                {"email": ["The Email Has no generated code"]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        is_code_valid = verify_code(email, validation_code)

        if not is_code_valid:
            return Response(
                {"code": ["Code is invalid or expired, you can request a new one"]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check for existing Username with the entered Username and Email
        # if it does, then send the user back to where they're coming from
        if (
            User.objects.filter(username=username).exists()
            or User.objects.filter(username=email).exists()
        ):
            return Response(
                {"username": ["Username must be unique for each user"]},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )
        # checking if an email matches the username or email the user is trying to use
        if (
            User.objects.filter(email=username).exists()
            or User.objects.filter(email=email).exists()
        ):
            return Response(
                {"email": ["Email must be unique, try a different e-mail"]},
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
        username_or_email: str = (
            request.data.get("username_or_email")
            if type(request.data.get("username_or_email")) == str
            else None
        )
        password: str = (
            request.data.get("password")
            if type(request.data.get("password")) == str
            else None
        )

        empty_values = {}
        if not (username_or_email and username_or_email.strip()):
            empty_values["username_or_email"] = [
                "This field is required and should be a string"
            ]

        if not (password and password.strip()):
            empty_values["password"] = ["This field is required and should be a string"]

        if len(empty_values) != 0:
            return Response(empty_values, status=status.HTTP_400_BAD_REQUEST)

        password = password.strip()
        username_or_email = username_or_email.strip()
        username: str

        if not confirmUserDetail(username_or_email):
            return Response(
                {"username_or_email": ["Invalid Username or Email"]},
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
                {"non_field_errors": ["Invalid Login Credentials"]},
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
            return Response(empty_values, status=status.HTTP_400_BAD_REQUEST)

        if Contest.objects.filter(name__iexact=name, created_by=request.user):
            return Response(
                {"name": ["A Contest with this name already exists"]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not levels.isdigit():
            return Response(
                {"levels": ["Must be a number"]},
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
        return Response(serializer.data, status=status.HTTP_200_OK)


# For GET, EDIT, DELETE requires pk parameter
class ContestView(APIView):
    permission_classes = [IsAuthenticated]

    # fetch a specific contest
    def get(self, request: Request, pk):
        if not check_uuid(pk):
            return Response(
                {"detail": "Invalid Id"}, status=status.HTTP_400_BAD_REQUEST
            )
        if not Contest.objects.filter(id=pk, created_by=request.user).exists():
            return Response(
                {"detail": "Contest not found or doesn't belong to authenticated user"},
                status=status.HTTP_404_NOT_FOUND,
            )
        contest = Contest.objects.get(pk=pk)

        serializer = ContestSerializer(contest)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request: Request, pk):
        if not check_uuid(pk):
            return Response(
                {"detail": "Invalid Id"}, status=status.HTTP_400_BAD_REQUEST
            )

        if not Contest.objects.filter(id=pk, created_by=request.user).exists():
            return Response(
                {"detail": "Contest not found or doesn't belong to authenticated user"},
                status=status.HTTP_404_NOT_FOUND,
            )
        contest = Contest.objects.get(pk=pk)

        contest.delete()
        return Response(
            {"detail": "Contest Deleted"}, status=status.HTTP_204_NO_CONTENT
        )

    def patch(self, request: Request, pk):
        if not check_uuid(pk):
            return Response(
                {"detail": "Invalid Id"}, status=status.HTTP_400_BAD_REQUEST
            )

        if not Contest.objects.filter(id=pk, created_by=request.user).exists():
            return Response(
                {"detail": "Not found or doesn't belong to authenticated user"},
                status=status.HTTP_404_NOT_FOUND,
            )
        contest = Contest.objects.get(pk=pk)

        name: str = request.data.get("name")

        if Contest.objects.filter(name__icontains=name).exclude(pk=pk).exists():
            return Response(
                {"name": ["A Contest with this name already exists"]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = ContestSerializer(contest, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"detail": "Contest Updated"}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ContestantsView(APIView):
    permission_classes = [IsAuthenticated]

    # Creating Contestant
    def post(self, request: Request, contest_id: str):

        if not check_uuid(contest_id):
            return Response(
                {"detail": "Invalid Contest Id"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not Contest.objects.filter(pk=contest_id, created_by=request.user):
            return Response(
                {
                    "detail": "Contest not found or doesn't belong to the authenticated user"
                },
                status=status.HTTP_404_NOT_FOUND,
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
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # get all user's contestants for a contest
    def get(self, request: Request, contest_id: str):
        if not check_uuid(contest_id):
            return Response(
                {"detail": "Invalid Contest Id"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not Contest.objects.filter(pk=contest_id, created_by=request.user).exists():
            return Response(
                {
                    "detail": "Contest not found or doesn't belong to the authenticated user"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        contest = Contest.objects.prefetch_related("contestants").get(
            pk=contest_id, created_by=request.user
        )
        search: str = request.query_params.get("search")
        contestants: Contestant
        if not (search and search.strip()):
            contestants = contest.contestants.all()

        else:
            search = search.strip()
            contestants = contest.contestants.all().filter(
                Q(name__icontains=search) | Q(contest__name__icontains=search)
            )

        serializer = ContestantSerializer(contestants, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


# to cater for delete, edit, update, fetching a specific contestant
class ContestantView(APIView):
    def get(self, request: Request, contestant_id: str):
        if not check_uuid(contestant_id):
            return Response(
                {"detail": "Invalid Contestant Id"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not Contestant.objects.filter(
            pk=contestant_id, contest__created_by=request.user
        ).exists():
            return Response(
                {
                    "non_field_errors": [
                        "Contestant not found or doesn't belong to the authenticated user"
                    ]
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        contestant: Contestant

        contestant = Contestant.objects.select_related("contest").get(
            pk=contestant_id, contest__created_by=request.user
        )
        serializer = ContestantSerializer(contestant)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request: Request, contestant_id: str):

        if not check_uuid(contestant_id):
            return Response(
                {"detail": "Invalid Contestant Id"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not Contestant.objects.filter(
            pk=contestant_id, contest__created_by=request.user
        ).exists():
            return Response(
                {
                    "non_field_errors": [
                        "Contestant not found or doesn't belong to the authenticated user"
                    ]
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
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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
                    "detail": "Contestant not found or doesn't belong to the authenticated user"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        contestant = Contestant.objects.get(
            pk=contestant_id, contest__created_by=request.user
        )
        contestant.delete()
        return Response({"detail": "Successfully Deleted"}, status=status.HTTP_200_OK)


def check_options(options: str | bool | None):
    if type(options) == str:
        options = options.replace(
            "'", '"'
        )  # to prevent the error I encountered doing json.loads()
    try:
        options: list[dict[str, any]] = (
            json.loads(options) if type(options) == str else options
        )
        # if after decoding it it's still not a list
        if not type(options) == list:
            return False
        for option in options:
            text: str = option.get("text")
            if not (text and type(text) == str and text.strip()):
                return False
            is_correct: bool = option.get("is_correct")
            is_correct = get_boolean_value(is_correct)
            if not type(is_correct) == bool:
                return False
        return True
    except:
        return False


def check_options_truth(options: list[dict[str, any]]):
    true_option_count = 0
    if options:
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


class QuestionsView(APIView):
    permission_classes = [IsAuthenticated]

    # getAll questions in a contest
    def get(self, request: Request, contest_id: str):
        search: str = request.query_params.get("search")
        search = search.strip() if search else ""
        if not check_uuid(contest_id):
            return Response(
                {"detail": "Invalid Contest ID"}, status=status.HTTP_400_BAD_REQUEST
            )
        if not Contest.objects.filter(pk=contest_id, created_by=request.user):
            return Response(
                {"detail": "Contest not found or doesn't belong to authenticated user"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        contest = Contest.objects.prefetch_related(
            Prefetch(
                "questions",
                queryset=Question.objects.prefetch_related("options").filter(
                    Q(text__icontains=search)
                    | Q(level__icontains=search)
                    | Q(contest__name__icontains=search)
                ),
            )
        ).get(pk=contest_id, created_by=request.user)

        questions = contest.questions.all()
        serializer = QuestionSerializer(questions, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

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
                    "detail": "Contest not found or doesn't belong to the authenticated user"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        contest = Contest.objects.get(pk=contest_id, created_by=request.user)
        text: str | None = (
            str(request.data.get("text")).strip() if request.data.get("text") else None
        )
        level: str | None = (
            request.data.get("level")
            if str(request.data.get("level")).isdigit()
            else None
        )
        has_option: bool | None = get_boolean_value(request.data.get("has_option"))
        options: str | list = (
            request.data.get("options") if request.data.get("options") else []
        )
        error_values = {}
        if not level:
            error_values["level"] = ["This field is required and Must be a Number"]
        if not text:
            error_values["text"] = ["This field is required"]

        # Validating different types of boolean requests
        if type(has_option) != bool:
            error_values["has_options"] = ["Should be either 'true' or 'false'"]

        options_are_valid = check_options(options)
        print(type(options))
        if options_are_valid and type(options) == str:
            options = str(options).replace("'", '"')
            options: list[dict, any] = json.loads(str(options))
        elif not options_are_valid:
            # if options are invalid and the has_options is set to true
            if has_option:
                error_values["options"] = ["Should be a valid list of option objects"]

        if has_option and not (type(options) == list):
            error_values["options"] = ["Options should be of list type '[]'"]

        if has_option and options_are_valid and not len(options) > 1:
            error_values["options"] = [
                "Options must be more than one when options are set"
            ]

        if len(error_values) != 0:
            return Response(error_values, status=status.HTTP_400_BAD_REQUEST)
        if has_option and not check_options_truth(options):
            return Response(
                {"option": ["Only one of the options can be true"]},
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

        if has_option:
            Option.objects.bulk_create(
                [
                    Option(
                        question=question,
                        text=option.get("text"),
                        is_correct=get_boolean_value(option.get("is_correct")),
                    )
                    for option in options
                ]
            )
        return Response(
            {"detail": "Question Added Successfully"}, status=status.HTTP_200_OK
        )


# A view that gets all the questions a user has created
class AllQuestionsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request: Request):
        search: str = request.query_params.get("search")
        search = search.strip() if search else ""

        questions = (
            Question.objects.prefetch_related("options")
            .select_related("contest")
            .filter(contest__created_by=request.user)
            .filter(
                Q(text__icontains=search)
                | Q(level__icontains=search)
                | Q(contest__name__icontains=search)
            )
        )

        serializer = QuestionSerializer(questions, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


# this view will work on delete, update and get a specific question
class QuestionView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request: Request, question_id: str):
        if not check_uuid(question_id):
            return Response(
                {"detail": "Invalid Question Id"}, status=status.HTTP_400_BAD_REQUEST
            )

        if not Question.objects.filter(
            pk=question_id, contest__created_by=request.user
        ).exists():
            return Response(
                {
                    "detail": "Question not found or doesn't belong to authenticated user"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        question = (
            Question.objects.prefetch_related("options")
            .select_related("contest")
            .get(pk=question_id)
        )
        serializer = QuestionSerializer(question)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request: Request, question_id: str):

        if not check_uuid(question_id):
            return Response(
                {"detail": "Invalid Question Id"}, status=status.HTTP_400_BAD_REQUEST
            )

        if not Question.objects.filter(
            pk=question_id, contest__created_by=request.user
        ).exists():
            return Response(
                {
                    "detail": "Question not found or doesn't belong to authenticated user"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        question: Question = (
            Question.objects.select_related("contest")
            .prefetch_related("options")
            .get(pk=question_id)
        )
        contest: Contest = question.contest

        text: str | None = (
            str(request.data.get("text")).strip() if request.data.get("text") else None
        )
        level: str | None = (
            request.data.get("level")
            if str(request.data.get("level")).isdigit()
            else None
        )

        has_option: bool | None = get_boolean_value(request.data.get("has_option"))

        options: str | list = (
            request.data.get("options") if request.data.get("options") else []
        )
        error_values = {}
        if not level:
            error_values["level"] = ["This field is required and Must be a Number"]
        if not text:
            error_values["text"] = ["This field is required"]

        # Validating different types of boolean requests
        if not type(has_option) == bool:
            error_values["has_options"] = ["Should be either 'true' or 'false'"]

        options_are_valid = check_options(options)

        if options_are_valid and type(options) == str:
            options = str(options).replace("'", '"')
            options: list[dict, any] = json.loads(str(options))
        elif not options_are_valid:
            # if options are invalid and the has_options is set to true
            if has_option:
                error_values["options"] = ["Should be a valid list of option objects"]

        if has_option and options_are_valid and not len(options) > 1:
            error_values["options"] = [
                "Options must be more than one when options are set"
            ]
        if len(error_values) != 0:
            return Response(error_values, status=status.HTTP_400_BAD_REQUEST)

        if has_option and not check_options_truth(options):
            return Response(
                {"option": ["Only one of the options can be true"]},
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

        previous_options: Option = question.options.all()

        question.has_option = has_option
        question.level = level
        question.text = text

        previous_options.delete()

        if has_option:
            Option.objects.bulk_create(
                Option(
                    question=question,
                    text=option.get("text"),
                    is_correct=get_boolean_value(option.get("is_correct")),
                )
                for option in options
            )
        question.save()

        return Response({"detail": "Question Updated"}, status=status.HTTP_200_OK)

    def delete(self, request: Request, question_id):
        if not check_uuid(question_id):
            return Response(
                {"detail": "Invalid Question Id"}, status=status.HTTP_400_BAD_REQUEST
            )

        if not Question.objects.filter(
            pk=question_id, contest__created_by=request.user
        ).exists():
            return Response(
                {
                    "detail": "Question not found or doesn't belong to authenticated user"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        question: Question = Question.objects.get(pk=question_id)
        question.delete()
        return Response(
            {"detail": "Question Deleted"}, status=status.HTTP_204_NO_CONTENT
        )


class RandomQuestionSelection(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request: Request, contest_id: str):
        if not check_uuid(contest_id):
            return Response(
                {"detail": "Invalid Contest ID"}, status=status.HTTP_400_BAD_REQUEST
            )

        contest_queryset = Contest.objects.prefetch_related("questions").filter(
            pk=contest_id, created_by=request.user
        )

        unscreened_level = request.query_params.get("level")

        level: int | None = (
            unscreened_level if str(unscreened_level).isdigit() else None
        )

        if not contest_queryset.exists():
            return Response(
                {
                    "detail": "Contest not found or doesn't belong to the authenticated user"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        contest = contest_queryset.get(pk=contest_id)

        if level:
            questions: QuerySet = contest.questions.filter(
                level=level, is_chosen=False
            )  # filter per level if applicable
        else:
            questions: QuerySet = contest.questions.filter(is_chosen=False)

        if not questions.count() > 0:
            return Response(
                {"detail": "No Available Question to Select"},
                status=status.HTTP_409_CONFLICT,
            )

        selected_question: Question = random.choice(questions)
        controller, created = ContestControl.objects.get_or_create(contest=contest)

        controller.current_question = selected_question

        selected_question.is_chosen = True
        controller.save()

        selected_question.save()
        controller = ContestControl.objects.select_related(
            "current_question", "contestant"
        ).get(id=controller.pk)
        serializer = ContestControlSerializer(controller)

        return Response(serializer.data, status=status.HTTP_200_OK)


# This end-point restores all selected questions and all contestants that might have been marked as disqualified
class ResetContestView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, contest_id: str):
        if not check_uuid(contest_id):
            return Response(
                {"detail": "Invalid Contest ID"}, status=status.HTTP_400_BAD_REQUEST
            )

        contest_queryset = Contest.objects.prefetch_related("questions").filter(
            pk=contest_id, created_by=request.user
        )

        if not contest_queryset.exists():
            return Response(
                {
                    "detail": "Contest not found or doesn't belong to the authenticated user"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        contest = contest_queryset.get(pk=contest_id)

        questions: QuerySet = contest.questions.all()
        questions.update(is_chosen=False)

        contestants: QuerySet = contest.contestants.all()
        contestants.update(is_qualified=True)

        controller, created = ContestControl.objects.get_or_create(contest=contest)

        controller.contestant = None
        controller.current_question = None
        controller.fifty_allowed = False
        controller.show_answer = False
        controller.display = False
        controller.last_admin_access = None
        controller.save()

        return Response({"detail": "Contest Has Been Reset"}, status=status.HTTP_200_OK)


class DisplaySpecificQuestionView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request: Request, contest_id):
        question_id = (
            str(request.data.get("question_id")).strip()
            if request.data.get("question_id")
            else None
        )

        if not check_uuid(contest_id):
            return Response(
                {"detail": "Invalid Contest Id"}, status=status.HTTP_400_BAD_REQUEST
            )

        if not Contest.objects.filter(pk=contest_id, created_by=request.user):
            return Response(
                {"detail": "Contest not found or doesn't belong to authenticated user"}
            )

        contest = Contest.objects.prefetch_related("questions", "control").get(
            pk=contest_id
        )

        if not question_id:
            return Response(
                {"question_id": ["This Field is required"]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not check_uuid(question_id):
            return Response(
                {"detail": "Invalid Question ID"}, status=status.HTTP_400_BAD_REQUEST
            )

        contest_questions: BaseManager[Question] = contest.questions.all()

        if not contest_questions.filter(pk=question_id).exists():
            return Response(
                {"detail": "Question not found or not part of the contest"},
                status=status.HTTP_404_NOT_FOUND,
            )

        question: Question = contest_questions.get(pk=question_id)
        controller: ContestControl = contest.control

        controller.current_question = question
        question.is_chosen = True
        question.save()
        controller.save()

        return Response(
            {"detail": "Display Question Set Successfully"}, status=status.HTTP_200_OK
        )
