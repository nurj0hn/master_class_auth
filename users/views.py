from drf_yasg.utils import swagger_auto_schema
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import response, mixins, viewsets, exceptions, generics, status
from .profile_exceptions import UserNotVerified
from django.contrib.auth import login as log, authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .serializers import (
    LoginSerializer,
    RegistrationSerializer,
    LogOutRefreshTokenSerializer,
    UserSerializer,
    LoginResponseSerializer,
    PublicUserSerializer,
    )


def get_login_response(user, request):
    refresh = RefreshToken.for_user(user)
    data = {
        "user": UserSerializer(instance=user, context={'request': request}).data,
        "refresh": str(refresh),
        "access": str(refresh.access_token)
    }
    return data

class RegistrationAPIView(generics.GenericAPIView):
    serializer_class = RegistrationSerializer

    def post(self, request):
        serializers = self.serializer_class(data=request.data)
        serializers.is_valid(raise_exception=True)
        serializers.save()
        user_data = serializers.data
        user = User.objects.get(username=user_data['username'])
        refresh = RefreshToken.for_user(user)
        data = {
            "user": UserSerializer(instance=user, context={'request': request}).data,
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }
        return Response(data, status=status.HTTP_201_CREATED)

class LoginAPIView(generics.GenericAPIView):
    authentication_classes = ()
    permission_classes = ()
    serializer_class = LoginSerializer

    @swagger_auto_schema(responses={'200': LoginResponseSerializer()}, tags=['auth'])
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = authenticate(username=serializer.validated_data['username'], password=serializer.validated_data['password'])
        if not user:
            raise exceptions.AuthenticationFailed()
        log(request, user)
        if request.user.is_verified == False:
            raise UserNotVerified()
        return response.Response(data=get_login_response(user, request))

class UsersView(generics.ListAPIView):
    serializer_class = PublicUserSerializer

    def get_queryset(self):
        return User.objects.all()

class LogoutView(generics.GenericAPIView):
    serializer_class = LogOutRefreshTokenSerializer
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args):
        sz = self.get_serializer(data=request.data)
        sz.is_valid(raise_exception=True)
        sz.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def get_queryset(self):
        pass