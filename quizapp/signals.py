from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from quizapp.registration_mails import send_success_reg
from django.conf import settings

User = get_user_model()


# Send Success Mail When the user completes registration
@receiver(post_save, sender=User)
def send_mail(sender, instance, created, **kwargs):
    if created:
        send_success_reg(
            to_mail=instance.email,
            username=instance.username,
            is_testing=settings.DEBUG,
        )
