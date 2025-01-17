from django.urls import path
from django.conf.urls import handler404, handler500
from . import views

urlpatterns = [
    path('', views.index, name="index"),
    path('home/', views.home, name='home'),  # Add this line for the home view
    path('login/', views.handle_login, name='handle_login'),  # Login handler
    path('signup/', views.handle_signup, name='handle_signup'),  # Signup handler
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('reset-password/', views.reset_password, name='reset_password'),
    path('login/', views.index, name='login'),  # Add this line for the login URL
    path('trigger-500/', views.trigger_500_error),
]

handler404 = 'delivery.views.custom_404_view'
handler500 = 'delivery.views.custom_500_view'

