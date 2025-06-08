import random
import string
import uuid
import urllib.parse
import re

# import openai

Ldap_strings = [
    ")(",
    "(&(",
    "(|(",
    "(||(",
    "*)",
    "*))",
]
OC_strings = [
    "bin",
    "tftp",
    "exe",
    "uftp",
    "/cdir",
    "dir",
    "/c ",
    "echo",
    "systeminfo",
    "/etc",
    "ping",
    "Wget",
    "nc",
    "rm",
    "&&",
    ";",
    ">",
    "system",
]
PT_strings = ["etc", "./", ".\\", "../", "~/", "/../"]
Sqli_strings = [
    "or",
    "union",
    "and",
    "INJECTED_PARAM",
    "select",
    "drop",
    "delete",
    "sqlmap",
    "else",
    "then",
    "from",
    "case",
    "when",
]
SSI_strings = [
    "set",
    "email",
    "<!--",
    "-->",
    "<!--#",
    "include",
    "cmd",
]
Xpath_strings = [
    "//*",
    "or",
    "and",
    "]|//",
    "]|",
    "substring",
    "extractvalue",
    "user",
    "name",
    "|[",
]
XSS_strings = [
    "window",
    "open",
    "document",
    "cookie",
    "iframe",
    "link",
    "rel",
    "object",
    "meta",
    "http-equiv",
    "<script",
    "onerror",
    "<img",
    "<input",
    "style",
    "<embed",
    "video",
    "eval",
    "alert",
]
SSH_strings = [
    # SSH
    "{:;};",
    "(){",
    "bash",
    ";}",
]

# def gpt(payload,prediction):

#     # 본인의 OpenAI API 키로 대체하세요
#     user_input = payload
#     prompt=user_input+" 이게 페이로드 값이고 이에 따른 웹 공격 탐지 결과가" + prediction+ "으로 탐지되었는데 그 이유가 무엇지인지 간결하게 5줄 이내로 한국어로 설명해"

#     messages = [
#         {
#             "role": "system",
#             "content": "You are a helpful assistant who is good at detailing."
#         },
#         {
#            "role": "user",
#             "content": prompt
#         }
#         ]
#         # OpenAI GPT 모델에 질문 전달
#     response = openai.ChatCompletion.create(
#         model="gpt-3.5-turbo",
#         messages=messages,

#        )


#         # GPT 모델의 첫 번째 답변 가져오기
#     gpt_response = ""
#     for choice in response.choices:
#       gpt_response += choice.message.content


#         # 대화 확장: 사용자와 어시스턴트 간의 추가 메시지
#     messages = [

#             {"role": "user", "content": user_input},
#             {"role": "assistant", "content": "페이로드에 대해 탐지된 공격 대처방안에 대해 8줄 이내로 짧게 설명해봐"},
#         ]

#         # 대화 확장을 위해 OpenAI GPT 모델에 추가 질문 전달
#     response = openai.ChatCompletion.create(
#         model="gpt-3.5-turbo",
#         messages=messages,
#         )

#         # 어시스턴트의 추가 응답 가져오기
#     assistant_response = response.choices[-1].message.content
#     #gpt_response = gpt_response.replace('다.', '다.\n')  # 예제: 마침표 뒤에 개행 문자 추가
#     #assistant_response = assistant_response.replace('다.', '다.\n')  # 예제: 마침표 뒤에 개행 문자 추가

#     return gpt_response, assistant_response


# 랜덤한 문자열을 생성하는 함수
def generate_random_string(length=8):
    letters_and_digits = string.ascii_letters + string.digits
    return "".join(random.choice(letters_and_digits) for _ in range(length))


def find_pattern_no_space(dataframe, column_name, target_string):
    # 대소문자를 구분하지 않고 탐지하기 위한 정규 표현식 패턴 설정
    pattern = re.compile(re.escape(target_string), re.IGNORECASE)
    # 데이터프레임의 열에서 정규 표현식 패턴과 일치하는 문자열 개수를 반환
    return dataframe[column_name].apply(lambda x: len(pattern.findall(str(x))))


# 원하는 패턴을 찾는 함수 정의
def find_pattern(dataframe, column_name, target_string):
    # 대소문자를 구분하지 않고 탐지하기 위한 정규 표현식 패턴 설정
    pattern = re.compile(re.escape(target_string) + r"\b", flags=re.IGNORECASE)

    # 데이터프레임의 열을 문자열로 변환한 후 정규 표현식 패턴과 일치하는 문자열 개수를 반환
    return dataframe[column_name].apply(lambda x: len(pattern.findall(str(x))))


# URL 디코딩 함수 정의
def url_decode(encoded_string):
    return urllib.parse.unquote(str(encoded_string))


def split_payload(payload):

    # 기본값 미리 할당
    method = ""
    uri = ""
    query = ""
    protocol = ""
    body = ""

    # ? 문자가 있을 때와 없을 때를 다루는 정규식 패턴
    pattern_with_question_mark = r"^(\w+)\s+([^?]+)\?(.*?)\s+HTTP/(\d+\.\d+)([\s\S]*)$"
    pattern_without_question_mark = r"^(\w+)\s+([^?]+)\s+HTTP/(\d+\.\d+)([\s\S]*)$"

    # ? 문자가 있을 때를 먼저 시도
    match_with_question_mark = re.match(pattern_with_question_mark, payload)
    if match_with_question_mark:
        method = match_with_question_mark.group(1)
        uri = match_with_question_mark.group(2)
        query = match_with_question_mark.group(3)
        protocol = match_with_question_mark.group(4)
        body = match_with_question_mark.group(5)
        # body 값에서 '\n'을 공백으로 대체
        body = body.replace(r"\n", " ")
    else:
        match_without_question_mark = re.match(pattern_without_question_mark, payload)
        if match_without_question_mark:
            method = match_without_question_mark.group(1)
            uri = match_without_question_mark.group(2)
            protocol = match_without_question_mark.group(3)
            body = match_without_question_mark.group(4)
            query = 0
            # body 값에서 '\n'을 공백으로 대체
            body = body.replace(r"\n", " ")

    return method, f"/{uri}", query, f"HTTP/{protocol}", body


def remove_whitespace(df_test):
    # 데이터프레임의 모든 열을 순회
    for column in ["URI", "QUERY", "BODY"]:
        # 열의 데이터 타입이 문자열인 경우에만 적용
        df_test[column] = df_test[column].str.replace(" ", "")
    return df_test


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


def calculate_sum(df, prediction):

    # 공격유형 파악하고 탐지할 문자열 배열 선택
    if prediction == "normal":
        return 0, 0, 0
    selected_array = select_attack_signatures(prediction)

    attack_sum_uri = 0
    attack_sum_query = 0
    attack_sum_body = 0
    for string in selected_array:
        attack_sum_uri += df[f"URI_{string}"][0]
        attack_sum_query += df[f"QUERY_{string}"][0]
        attack_sum_body += df[f"BODY_{string}"][0]

    return attack_sum_uri, attack_sum_query, attack_sum_body


def extract_attack_strings(prediction, df):  # area 1: uri , 2 : query , 3 : body
    # 이 함수에서 예측된 결과에 따른 문자열들을 추출할 예정
    selected_array = []

    selected_array = select_attack_signatures(prediction)

    uri_attack_array = []
    query_attack_array = []
    body_attack_array = []

    uri_attack_array = find_attack_string("URI", uri_attack_array, selected_array, df)
    query_attack_array = find_attack_string(
        "QUERY", query_attack_array, selected_array, df
    )
    body_attack_array = find_attack_string(
        "BODY", body_attack_array, selected_array, df
    )

    return uri_attack_array, query_attack_array, body_attack_array


def find_attack_string(attack_area, attack_array, selected_array, df):
    for string in selected_array:
        if df[f"{attack_area}_{string}"][0] > 0:
            attack_array.append(string)

    return attack_array
