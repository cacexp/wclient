from rest_framework.views import APIView
from rest_framework.authentication import BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

class UserView(APIView):
    authentication_classes = [BasicAuthentication]
    permission_classes = [IsAuthenticated]
    content_type="application/json"

    @csrf_exempt
    def get(self, request, id, format=None):
        data = {
            "name": "John",
            "surname": "Smith"
        }
        response = JsonResponse(data, status=200)
        response.set_cookie("was_here", "Yesyou", expires="Wed, 15-Nov-23 09:13:29 GMT")
        return response


class AuthView(APIView):
    
    content_type="application/json"

    @csrf_exempt
    def get(self, request, format=None):
        data = {
            "auth": "Basic",
        }
        response = JsonResponse(data, status=200)
        return response