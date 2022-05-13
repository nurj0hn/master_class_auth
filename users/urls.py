from django.urls import path
from users import views


urlpatterns = [
    path('register/', views.RegistrationAPIView.as_view()),
    path('login/', views.LoginAPIView.as_view()),
    path('logout/', views.LogoutView.as_view()),
    path('', views.UsersView.as_view())

]
