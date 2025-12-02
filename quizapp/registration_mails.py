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
    
<section style="background:whitesmoke;padding:20px;">
    <div style="padding:10px;background:white;border-radius:5px;">
        <p>Hi there,</p>

        <p>To continue with your sign-in/registration on <b>QUIZUP</b>,<br />
        please use the verification code below:</p>

        <p>🔐 Your Verification Code: {code.replace(" ", "",-1)}</p>
        <h2>{code}</h2>

        <br />
        <p>This code will expire in <b>{expires_in_minutes} minutes.</b></p>

        <p>If you didn't request this code, you can safely ignore this email.</p>

        <p>Thanks,</p>
        <p>The Quizup Team</p>

        <hr>
        {"<p><b>Note:</b> The application is still being tested and <b>NOT YET</b> in production</p>" if is_testing else ""}
    </div>
</section> 
"""
    text_content = strip_tags(html_content)

    msg = EmailMultiAlternatives(subject, text_content, from_mail, to_mails)

    msg.attach_alternative(html_content, "text/html")

    try:
        msg.send()
        return True
    except:
        return False


def send_success_reg(to_mail: str, username: str, is_testing=False):
    subject = "SUCCESSFUL QUIZUP REGISTRATION"
    to_mails = [to_mail]
    html_content = f"""
<section style="background:whitesmoke;padding:20px;">
    <div style="padding:10px;background:white;border-radius:5px;">
        <p>Hi, <b>{username}</b></p>

        <p>This is to inform you that your QUIZUP account has been successfully created</p>

        <p>You can now login your username or email and password</p>

        <p><b>Username:</b> <q>{username}</q></p>
        <p><b>Email:</b> <q>{to_mail}</q></p>

        <p>Thanks,</p>
        <p>The Quizup Team</p>

        <hr>
        {"<p><b>Note:</b> The application is still being tested and <b>NOT YET</b> in production</p>" if is_testing else ""}
    </div>
</section>    
"""
    text_content = strip_tags(html_content)

    msg = EmailMultiAlternatives(subject, text_content, from_mail, to_mails)

    msg.attach_alternative(html_content, "text/html")

    try:
        msg.send()
        return True
    except:
        return False
