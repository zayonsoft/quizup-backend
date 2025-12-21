from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
import uuid
from django.utils.timezone import now
from datetime import timedelta
from quizapp.utils import generate_random_chars
from django.db import IntegrityError
from django.core.exceptions import ValidationError
from django.conf import settings
from django.db.models import CheckConstraint, Q


class User(AbstractUser):
    id = models.UUIDField(
        primary_key=True, unique=True, default=uuid.uuid4, editable=False
    )
    email = models.EmailField(unique=True, blank=True)

    groups = models.ManyToManyField(
        Group, related_name="quizapp_user_groups", blank=True
    )
    user_permissions = models.ManyToManyField(
        Permission, related_name="quizapp_user_permissions", blank=True
    )

    def clean(self):
        super().clean()

        if User.objects.filter(email=self.username).exclude(pk=self.pk).exists():
            raise ValidationError({"email": "Email cannot be another user's username"})

        if User.objects.filter(username=self.email).exclude(pk=self.pk).exists():
            raise ValidationError(
                {"username": "Username cannot be another user's email"}
            )

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)


def generate_contest_code():
    while True:
        generated_string = generate_random_chars(8)
        if not Contest.objects.filter(code=generated_string).exists():
            return generated_string


class Contest(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=700)
    levels = models.IntegerField(default=1)
    code = models.CharField(unique=True, default=generate_contest_code, editable=False)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, editable=False
    )
    date_created = models.DateTimeField(auto_now_add=True, editable=False)

    # create a db constraint for created_by and name so that the current user
    #  cannot create multiple contests with the same name

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["name", "created_by"],
                name="unique_user_contest",
            ),
            CheckConstraint(condition=Q(levels__gte=1), name="min_number_of_levels"),
        ]

    def save(self, *args, **kwargs):
        for _ in range(6):
            try:
                return super().save(*args, **kwargs)
            except IntegrityError:
                self.key = generate_contest_code()
        raise IntegrityError("Failed to generate unique model key after retries")


class Question(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    contest = models.ForeignKey(
        Contest, on_delete=models.CASCADE, related_name="questions"
    )
    text = models.TextField()
    level = models.IntegerField()
    is_chosen = models.BooleanField(default=False)
    has_option = models.BooleanField(default=False)
    time_added = models.DateTimeField(auto_now_add=True)
    time_edited = models.DateTimeField(null=True)

    def save(self, *args, **kwargs):
        if not self._state.adding:
            self.time_edited = now()
        super().save(*args, **kwargs)


class Option(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    text = models.TextField()
    is_correct = models.BooleanField(default=False)
    question = models.ForeignKey(
        Question, on_delete=models.CASCADE, related_name="options"
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["question"],
                condition=Q(is_correct=True),
                name="one_correct_answer_per_question",
            )
        ]


class Contestant(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    contest = models.ForeignKey(
        Contest, on_delete=models.CASCADE, related_name="contestants"
    )
    name = models.CharField(max_length=700)
    is_qualified = models.BooleanField(default=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["contest", "name"],
                name="unique_contest_contestant",
            )
        ]


class ContestControl(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    contest = models.OneToOneField(
        Contest, on_delete=models.CASCADE, related_name="control"
    )
    contestant = models.OneToOneField(
        Contestant, on_delete=models.SET_NULL, null=True, blank=True
    )
    current_question = models.OneToOneField(
        Question, on_delete=models.SET_NULL, null=True, blank=True
    )
    fifty_allowed = models.BooleanField(default=False)
    show_answer = models.BooleanField(default=False)
    display = models.BooleanField(default=False)
    last_admin_access = models.DateTimeField(blank=True, null=True)

    def clean(self):
        if (
            not self._state.adding
            and self.contestant
            and (self.contest != self.contestant.contest)
        ):
            return ValidationError(
                {"contestant": "Contestant is not part of the contest"}
            )

    def save(self, *args, **kwargs):
        self.full_clean()
        self.last_admin_access = now()
        super().save(*args, **kwargs)


def ten_minutes_from_now():
    return now() + timedelta(minutes=10)


class UserMailValidator(models.Model):
    email = models.EmailField(unique=True, editable=False)
    otp_hash = models.CharField(max_length=100, editable=False, null=True)
    otp_salt = models.CharField(max_length=100, editable=False, null=True)
    otp_expires = models.DateTimeField(default=ten_minutes_from_now)
