from django.shortcuts import render
from django.db import connection
from django.db.models.expressions import RawSQL
from .models import Student

# Create your views here.


def index(request):
    if request.method == "GET":
        context = {'results': ''}
        return render(request, 'sqli.html', context)
    elif request.method == "POST":
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        try:
            student = Student.objects.get(username=username, password=password)
            results = True
        except Student.DoesNotExist:
            results = False

        return render(request, 'sqli.html', {'results': results})
    else:
        return "Error"