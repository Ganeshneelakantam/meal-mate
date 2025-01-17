# forms.py
from django import forms

class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(label="Enter your email", max_length=100)

class OTPForm(forms.Form):
    otp = forms.CharField(label="Enter OTP", max_length=6)

class NewPasswordForm(forms.Form):
    new_password = forms.CharField(widget=forms.PasswordInput, label="New Password")
    confirm_password = forms.CharField(widget=forms.PasswordInput, label="Confirm Password")
