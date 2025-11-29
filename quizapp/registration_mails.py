from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django.utils.html import strip_tags

from_mail = settings.EMAIL_HOST_USER


def send_validation_code(
    to_mail: str, code: str, expires_in_minutes=10, is_testing=False
):
    subject = "Your Quizup Verification Code"
    to_mails = [to_mail]
    html_content = f"""
<p>Hi,</p>

<p>To continue with your sign-in/registration on <b>QUIZUP</b>,<br />
please use the verification code below:</p>

<p>🔐 Your Verification Code:</p>
<h2>{code}</h2>

<br />
<p>This code will expire in <b>{expires_in_minutes} minutes.</b></p>

<p>If you didn't request this code, you can safely ignore this email.</p>

<p>Thanks,</p>
<p>The Quizup Team</p>

<hr>
{"<p><b>Note:</b> The application is still being tested and <b>NOT YET</b> in production</p>" if is_testing else ""}
"""
    text_content = strip_tags(html_content)

    msg = EmailMultiAlternatives(subject, text_content, from_mail, to_mails)

    msg.attach_alternative(html_content, "text/html")

    try:
        msg.send()
        return True
    except:
        return False
