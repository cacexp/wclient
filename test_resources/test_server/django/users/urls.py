from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from users import views

urlpatterns = [
    path('users/<int:id>/', views.UserView.as_view()),
    path('auth/auth.json', views.AuthView.as_view()),

]

urlpatterns = format_suffix_patterns(urlpatterns)