# views.py
#from telnetlib import LOGOUT
from base64 import urlsafe_b64decode, urlsafe_b64encode
from email.message import EmailMessage
import imp
from lib2to3.pgen2.tokenize import generate_tokens
from readline import get_current_history_length
from django.conf import settings
from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate,login,logout
from django.core.mail import send_mail,EmailMessage
from django.contrib.sites.shortcuts import get_current_site
import authentication
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes,force_text
from gfg import settings
from .tokens import generate_token

# Create your views here.
def home(request):
   return render(request,"authentication/index.html")    
def signup(request):

    if request.method == "POST":
        #username = request.POST.get('username')
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']

        if User.objects.filter(username=username):
            messages.error(request,"Username alrady exist")
            return redirect('home')
        if User.objects.filter(email=email):
            messages.error(request,"email already registered")    
        if pass1 != pass2 :
            messages.error(request,"passwords didn't match")            
        #create take one positional argument
        myuser = User.objects.create_user(username,email,pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active=False
        myuser.save()
        #confirmation messege
        messages.success(request,"Your account has been succesfully created")

        subject ="Welcome to GFG login"
        message = "Hello" + myuser.first_name+"!!"
        from_email = settings.EMAIL_HOST_USER
        to_list =[myuser.email]
        send_mail(subject,message,from_email,to_list,fail_scilently=True)

        #confirmation email

        current_site = get_current_site(request)
        email_subject = "confirm your email @Django_login"
        message2=render_to_string('email_confirmation.html',{
            'name':myuser.first_name,
            'domain':current_site.domain,
            'uid':urlsafe_b64encode(force_bytes(myuser.pk)),
            'token':generate_token.make_token(myuser)
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],
        )
        email.fail_silently=True
        email.send()


        #after user signup redirected to login page
        return redirect('signin')


    return render(request,"authentication/signup.html")    
def signin(request):

    if request.method == 'POST':
        username = request.POST['username']
        pass1 = request.POST['pass1']

        user = authenticate(username=username, password=pass1)
        if user is not None:
            login(request,user)
            fname = user.first_name
            return render(request,"authentication/index.html",{'fname':fname})
        else:
            messages.error(request, "BadCredentials")
            return redirect('home')

    return render(request,"authentication/signin.html")  
def signout(request):
     logout(request)
     messages.success(request,"Logged Out Successfully")
     return redirect('home')
def activate(request,uidb64,token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser=None
    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        myuser.save()
        login(request,myuser)
        return redirect('home')
    else:
        return render(request,'activation_failed.html')            
