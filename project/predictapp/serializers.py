from rest_framework import serializers


class PredictionRequestSerializer(serializers.Serializer):
    payload = serializers.CharField(
        default="POST /search HTTP/1.1\nHost: vulnerable.site\nContent-Type: application/x-www-form-urlencoded\n\nq=<script>alert('x')</script>"
    )


class PredictionResponseSerializer(serializers.Serializer):
    predictedType = serializers.CharField()
    ldapInjection = serializers.FloatField()
    osCommanding = serializers.FloatField()
    pathTraversal = serializers.FloatField()
    ssi = serializers.FloatField()
    shellShock = serializers.FloatField()
    sqlInjection = serializers.FloatField()
    xpathInjection = serializers.FloatField()
    xss = serializers.FloatField()
    normal = serializers.FloatField()

    detectedString = serializers.ListField(child=serializers.CharField())
    payload = serializers.CharField()
