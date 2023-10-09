from rest_framework import generics, permissions
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from .serializers import LoginSerializer , RegSerializer , ProfileSerializer
from .models import MyUser
from rest_framework import status
from django.contrib.auth import authenticate, login

User = get_user_model()

class UserProfileView(generics.RetrieveUpdateAPIView):
    queryset = MyUser.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

class RegisterView(generics.CreateAPIView):
    queryset = MyUser.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = RegSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

class LoginView(generics.CreateAPIView):
    queryset = MyUser.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = LoginSerializer

    def create(self, request, *args, **kwargs):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(request, username=email, password=password)

        if user is not None:
            login(request, user)
            serializer = LoginSerializer(user)
            return Response(serializer.data)
        else:
            return Response({'error'}, status=status.HTTP_401_UNAUTHORIZED)
