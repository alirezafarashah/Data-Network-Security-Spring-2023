from django.contrib import admin
from .models import Student


# Register your models here.
class StudentAdmin(admin.ModelAdmin):
    list_display = ('username', 'password')
    list_filter = ('username',)
    search_fields = ('username',)
    

admin.site.register(Student, StudentAdmin)