from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from land.models import User
from rest_framework import serializers
from land import models
from django.utils import timezone


# ==========================================================================================================================
# Serializers Modelos User Depth = 0
# ==========================================================================================================================


class UserSerializer(serializers.ModelSerializer):
    fecha_registro = serializers.DateTimeField(
        format="%Y-%m-%d %H:%M:%S", required=False
    )
    ultimo_login = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", required=False)

    class Meta:
        ordering = ["id"]
        model = models.User
        fields = "__all__"
        depth = 0


# ==========================================================================================================================
# Serializers Modelos User Depth = 1
# ==========================================================================================================================


class UserDepthSerializer(serializers.ModelSerializer):
    fecha_registro = serializers.DateTimeField(
        format="%Y-%m-%d %H:%M:%S", required=False
    )
    ultimo_login = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", required=False)

    class Meta:
        ordering = ["id"]
        model = models.User
        fields = "__all__"
        depth = 1


# ==========================================================================================================================
# Serializers Token
# ==========================================================================================================================


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)

        # Actualizamos el último login
        self.user.ultimo_login = timezone.now()
        self.user.save(update_fields=["ultimo_login"])

        data["id"] = self.user.id
        data["username"] = self.user.username if self.user.username else ""
        data["email"] = self.user.email
        data["nombre"] = self.user.first_name
        data["apellido"] = self.user.last_name
        # agregar información sobre si es super usuario
        data["superusuario"] = self.user.is_superuser

        return data
