from django.shortcuts import render
from django.views.decorators.http import require_POST

# Create your views here.
def index(request):
    return render(request, "xss.html")

def l1(request):
    if request.method == "GET":
        context = {'name': 'Anonymous User'}
        #template = loader.get_template("./xss/templates/xss_l1.html")
        return render(request, 'xss_l1.html', context)
    elif request.method == "POST":
        name = request.POST.get('name', 'Anonymous User')
        context = {'name': name}
        return render(request, 'xss_l1.html', context)
    else:
        return "Error"

def l2(request):
    if request.method == "GET":
        context = {'name': 'Anonymous User'}
        #template = loader.get_template("./xss/templates/xss_l2.html")
        return render(request, 'xss_l2.html', context)
    elif request.method == "POST":
        name = request.POST.get('name', 'Anonymous User')
        context = {'name': name}
        return render(request, 'xss_l2.html', context)
    else:
        return "Error"

    