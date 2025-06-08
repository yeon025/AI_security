from django.urls import path
from predictapp.views import predict_type

urlpatterns = [
    path("predict/", predict_type),
]
