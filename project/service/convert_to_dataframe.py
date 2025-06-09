import re
import pandas as pd


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


# 우리가 정한 데이터셋 컬럼 양식에 맞게 전처리
def convert_string(payload):
    # 빈 데이터프레임 생성
    df = pd.DataFrame(columns=["1"])
    # 문자열을 데이터프레임에 추가 (1행 1열에 저장)
    df.loc[0, "1"] = payload
    df_payload = pd.DataFrame()
    df_payload[["METHOD", "URI", "QUERY", "PROTOCOL", "BODY"]] = df.iloc[:, 0].apply(
        lambda x: pd.Series(split_payload(x))
    )

    return df_payload
