from rest_framework import serializers


class PredictionSerializer(serializers.Serializer):
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
