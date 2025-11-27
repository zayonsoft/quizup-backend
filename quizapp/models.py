from django.db import models
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractUser
import uuid
from django.utils.timezone import now
from datetime import timedelta
from quizapp.utils import generate_random_chars
from django.db import IntegrityError
from django.core.exceptions import ValidationError

User = get_user_model()


class User(AbstractUser):
    id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, blank=True)

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
    name = models.CharField(max_length=700)
    levels = models.IntegerField(default=1)
    code = models.CharField(unique=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    date_created = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        for _ in range(6):
            try:
                return super().save(*args, **kwargs)
            except IntegrityError:
                self.key = generate_contest_code()
        raise IntegrityError("Failed to generate unique model key after retries")


class Question(models.Model):
    contest = models.ForeignKey(Contest, on_delete=models.CASCADE)
    level = models.IntegerField()
    is_chosen = models.BooleanField(default=False)
    has_option = models.BooleanField(default=False)
    time_added = models.DateTimeField(auto_now_add=True)
    time_edited = models.DateTimeField(blank=True)


class Option(models.Model):
    text = models.TextField()
    is_correct = models.BooleanField(default=False)
    question = models.ForeignKey(Question, on_delete=models.CASCADE)


class Contestant(models.Model):
    contest = models.ForeignKey(Contest, on_delete=models.CASCADE)
    name = models.CharField(max_length=700)
    is_qualified = models.BooleanField(default=True)


class ContestControl(models.Model):
    contest = models.OneToOneField(Contest, on_delete=models.CASCADE)
    current_question = models.OneToOneField(
        Question, on_delete=models.SET_NULL, null=True
    )
    fifty_allowed = models.BooleanField(default=False)
    show_answer = models.BooleanField(default=False)
    last_admin_access = models.DateTimeField(blank=True, null=True)


def ten_minutes_from_now():
    return now() + timedelta(minutes=10)


class UserMailValidator(models.Model):
    email = models.EmailField(unique=True)
    otp_hash = models.CharField(max_length=100, editable=False, null=True)
    otp_salt = models.CharField(max_length=100, editable=False, null=True)
    otp_expires = models.DateTimeField(default=ten_minutes_from_now)
