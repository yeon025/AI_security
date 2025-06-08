from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
from service.preprocessing import (
    convert_dataframe,
    preprocessing,
    predict,
    detect_attack_area,
    detect_attack_string,
)
from .serializers import PredictionSerializer


# Create your views here.
@api_view(["POST"])
def predict_type(request):
    payload = request.data.get("payload")

    converted_payload = convert_dataframe(payload)

    test_X = preprocessing(converted_payload)

    predicted_type, probs = predict(test_X)

    attack_sum_uri, attack_sum_query, attack_sum_body = detect_attack_area(
        test_X, predicted_type
    )

    uri_attack_array, query_attack_array, body_attack_array = detect_attack_string(
        predicted_type, test_X
    )

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
        "uriAttackArray": uri_attack_array,
        "queryAttackArray": query_attack_array,
        "bodyAttackArray": body_attack_array,
        "uri": attack_sum_uri,
        "query": attack_sum_query,
        "body": attack_sum_body,
    }
    result_serializer = PredictionSerializer(result)

    return Response(result_serializer.data)
