from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from service.convert_to_dataframe import convert_string
from service.preprocessing import preprocessing
from service.predict import predict, detect_attack_string
from .serializers import PredictionSerializer


# Create your views here.
@api_view(["POST"])
def predict_type(request):
    payload = request.data.get("payload")

    # payload를 데이터프레임으로 변환
    converted_payload = convert_string(payload)

    # 전처리
    preprocessed_data = preprocessing(converted_payload)

    # 공격 유형 예측과 공격 유형에 속할 확률을 계산
    predicted_type, probs = predict(preprocessed_data)

    # 문자열 탐지
    detected_string = detect_attack_string(predicted_type, preprocessed_data)

    # 직렬화
    result = {
        "predictedType": predicted_type,
        "ldapInjection": round(probs[0][0], 2),
        "osCommanding": round(probs[0][1], 2),
        "pathTraversal": round(probs[0][2], 2),
        "ssi": round(probs[0][3], 2),
        "shellShock": round(probs[0][4], 2),
        "sqlInjection": round(probs[0][5], 2),
        "xpathInjection": round(probs[0][6], 2),
        "xss": round(probs[0][7], 2),
        "normal": round(probs[0][8], 2),
        "detectedString": detected_string,
    }
    result_serializer = PredictionSerializer(result)

    return Response(result_serializer.data)
