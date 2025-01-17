from urllib import request
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password, check_password
from delivery.models import User  # Use your custom User model
from django.views.decorators.cache import cache_control
from django.core.mail import send_mail
from django.conf import settings
from random import randint
from .forms import ForgotPasswordForm, OTPForm, NewPasswordForm

# Create your views here.
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def index(request):
    return render(request, 'delivery/index.html')

def handle_login(request):
    if request.method == 'POST':
        # Get the username and password from the POST request
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            # Fetch the user from the database
            user = User.objects.get(username=username)

            # Check if the provided password matches the hashed password in the database
            if check_password(password, user.password):
                # Password is correct, log the user in
                request.session['username'] = user.username
                return redirect('home')  # Redirect to a home page or dashboard
            else:
                error_message = "Invalid username or password!"
        except User.DoesNotExist:
            error_message = "Invalid username or password!"
        
        return render(request, 'delivery/index.html', {'error_message': error_message})
    else:
        return render(request, 'delivery/index.html')

def handle_signup(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        mobile = request.POST.get('mobile')
        password = make_password(request.POST.get('password'))
        address = request.POST.get('address')
        user = User(
            username=username,
            email=email,
            mobile=mobile,
            password=password,
            address=address
        )
        user.save()
        # Send a welcome email
        subject = "Welcome to Meal-Mate!"
        message = f"""
        Hi {username},

        Thank you for registering with Meal-Mate! We're thrilled to have you on board.

        Explore delicious meals and enjoy the best service we offer.

        If you have any questions, feel free to reach out to us at {settings.EMAIL_HOST_USER}.

        Happy dining,
        The Meal-Mate Team
        """
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [email]
        
        try:
            send_mail(subject, message, from_email, recipient_list, fail_silently=False)
        except Exception as e:
            # Log or handle the email failure here
            print(f"Error sending email: {e}")
        
        return render(request, 'delivery/index.html', {'success_message': "Account created successfully!"})
    else:
        return HttpResponse("Invalid request")

# Store OTP temporarily in a global variable (you can use session for production)
otp_store = {}

def forgot_password(request):
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
                # Generate OTP
                otp = str(randint(100000, 999999))
                otp_store[email] = otp  # Store OTP temporarily
                send_mail(
                    'Your OTP for Meal-Mate Password Reset',
                    f'Your OTP is: {otp}',
                    settings.EMAIL_HOST_USER,
                    [email],
                    fail_silently=False,
                )
                request.session['email'] = email  # Store the email in the session
                return redirect('verify_otp')
            except User.DoesNotExist:
                form.add_error('email', 'Email not found')
    else:
        form = ForgotPasswordForm()
    return render(request, 'delivery/forgot_password.html', {'form': form})

def verify_otp(request):
    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            entered_otp = form.cleaned_data['otp']
            email = request.session.get('email')  # Get the email from session
            if email and otp_store.get(email) == entered_otp:
                return redirect('reset_password')
            else:
                form.add_error('otp', 'Invalid OTP')
    else:
        form = OTPForm()
    return render(request, 'delivery/verify_otp.html', {'form': form})

def reset_password(request):
    if request.method == 'POST':
        form = NewPasswordForm(request.POST)
        if form.is_valid():
            new_password = form.cleaned_data['new_password']
            confirm_password = form.cleaned_data['confirm_password']
            if new_password == confirm_password:
                email = request.session.get('email')
                if email:
                    try:
                        user = User.objects.get(email=email)
                        user.password = make_password(new_password)  # Hash the new password
                        user.save()
                        del request.session['email']
                        return redirect('login')
                    except User.DoesNotExist:
                        form.add_error(None, 'User not found')
                else:
                    form.add_error(None, 'No email found in session')
            else:
                form.add_error('confirm_password', 'Passwords do not match')
    else:
        form = NewPasswordForm()
    return render(request, 'delivery/reset_password.html', {'form': form})

def home(request):
    username = request.session.get('username', 'Guest')
    return render(request, 'delivery/home.html', {'username': username})

def handle_logout(request):
    request.session.flush()
    return redirect('login')

from django.core.cache import cache

def send_otp(email):
    otp = str(randint(100000, 999999))
    cache.set(email, otp, timeout=300)  # 5 minutes


from django.contrib.auth import logout
from django.shortcuts import redirect

def handle_logout(request):
    """
    Logs out the user and redirects them to the login page.
    """
    logout(request)  # This logs out the current user
    return redirect('login')  # Redirect to the login page


def custom_404_view(request, exception):
    return render(request, '404.html', status=404)

def custom_500_view(request):
    return render(request, '500.html', status=500)

def trigger_500_error(request):
    raise Exception("Simulating a server error")
