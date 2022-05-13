from .models import User
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken, TokenError


class PasswordField(serializers.CharField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('style', {})

        kwargs['style']['input_type'] = 'password'
        kwargs['write_only'] = True

        super().__init__(*args, **kwargs)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            'id', 'username', 'date_joined')
        read_only_fields = ('date_joined',)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # print(instance)
        return data


class LoginResponseSerializer(serializers.Serializer):
    user = UserSerializer()
    refresh = serializers.CharField()
    access = serializers.CharField()


class RegistrationSerializer(serializers.ModelSerializer):
    password = PasswordField(required=True, allow_blank=False, allow_null=False)
    password2 = PasswordField(required=True, allow_blank=False, allow_null=False)
    class Meta:
        model = User
        fields = ['id', 'username', 'password', 'password2']

        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        account = User(username=self.validated_data['username'],)

        password = self.validated_data['password']
        password2 = self.validated_data['password2']

        if password != password2:
            raise serializers.ValidationError({'password': 'Password must much'})
        account.set_password(password)
        account.is_verified=True
        account.save()
        return account


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=255, min_length=3)
    password = PasswordField(required=True, allow_blank=False, allow_null=False)


class LogOutRefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_messages = {'bad_token': ('Token is invalid or expired')}

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')


class PublicUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'date_joined')