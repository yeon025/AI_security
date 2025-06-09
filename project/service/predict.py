import joblib
from .lists import (
    Ldap_strings,
    OC_strings,
    PT_strings,
    Sqli_strings,
    SSI_strings,
    Xpath_strings,
    XSS_strings,
    SSH_strings,
)
import warnings

warnings.filterwarnings("ignore")


# 모델 로드
model = joblib.load("pkl/ensemble_model.pkl")


# 공격 유형 예측과 공격 유형에 속할 확률을 계산
def predict(preprocessed_data):
    prediction = model.predict(preprocessed_data)
    prediction = ", ".join(prediction)

    probs = model.predict_proba(preprocessed_data)

    return prediction, probs


# 문자열 탐지
def select_attack_signatures(prediction):
    if prediction == "LdapInjection":
        selected_array = Ldap_strings
    elif prediction == "OsCommanding":
        selected_array = OC_strings
    elif prediction == "PathTraversal":
        selected_array = PT_strings
    elif prediction == "SqlInjection":
        selected_array = Sqli_strings
    elif prediction == "SSI":
        selected_array = SSI_strings
    elif prediction == "XPathInjection":
        selected_array = Xpath_strings
    elif prediction == "XSS":
        selected_array = XSS_strings
    elif prediction == "Shellshock":
        selected_array = SSH_strings
    return selected_array


def find_attack_string(attack_area, detect_array, selected_array, dataframe):
    for string in selected_array:
        if dataframe[f"{attack_area}_{string}"][0] > 0:
            detect_array.append(string)

    return detect_array


# 이 함수에서 예측된 결과에 따른 문자열들을 추출
def detect_attack_string(prediction, dataframe):
    selected_array = []

    selected_array = select_attack_signatures(prediction)

    detect_array = []

    detect_array = find_attack_string("URI", detect_array, selected_array, dataframe)
    detect_array = find_attack_string("QUERY", detect_array, selected_array, dataframe)
    detect_array = find_attack_string("BODY", detect_array, selected_array, dataframe)

    return detect_array
