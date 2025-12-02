from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from quizapp.registration_mails import send_success_reg
from django.conf import settings
from django.contrib.auth.models import AbstractUser

User = get_user_model()


# converts the E-mail field to lowercase before saving
@receiver(pre_save, sender=User)
def lower_email(sender, instance: AbstractUser, **kwargs):
    if instance.email:
        instance.email = instance.email.lower()


# Send Success Mail When the user completes registration
@receiver(post_save, sender=User)
def send_mail(sender, instance: AbstractUser, created, **kwargs):
    if created:
        send_success_reg(
            to_mail=instance.email,
            username=instance.username,
            is_testing=settings.DEBUG,
        )
