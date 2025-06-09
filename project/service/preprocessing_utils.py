import pandas as pd
import urllib.parse
import joblib
import re
from .lists import target_strings, target_strings_2

# 모델 로드
one_hot_encoder = joblib.load("pkl/one_hot_encoder.pkl")
tfidf_vectorizer = joblib.load("pkl/tfidf_model.pkl")
cluster_encoder = joblib.load("pkl/cluster_encoder.pkl")
kmeans = joblib.load("pkl/kmeans_model.pkl")


def find_pattern_no_space(dataframe, column_name, target_string):
    # 대소문자를 구분하지 않고 탐지하기 위한 정규 표현식 패턴 설정
    pattern = re.compile(re.escape(target_string), re.IGNORECASE)
    # 데이터프레임의 열에서 정규 표현식 패턴과 일치하는 문자열 개수를 반환
    return dataframe[column_name].apply(lambda x: len(pattern.findall(str(x))))


def count_newline_encodings_per_column(dataframe):
    # 탐지할 문자열 리스트 설정
    newline_encodings = ["%0D%0A", "%0D", "%0A"]

    # 'QUERY', 'BODY' 컬럼에서 탐지 문자열들의 빈도수 계산
    for target in newline_encodings:
        dataframe[f"QUERY_{target}"] = find_pattern_no_space(dataframe, "QUERY", target)
        dataframe[f"BODY_{target}"] = find_pattern_no_space(dataframe, "BODY", target)
        dataframe[f"URI_{target}"] = find_pattern_no_space(dataframe, "URI", target)
        dataframe[f"URI&BODY&QUERY_{target}"] = (
            dataframe[f"QUERY_{target}"]
            + dataframe[f"BODY_{target}"]
            + dataframe[f"URI_{target}"]
        )
    return dataframe


# URL 디코딩 함수 정의
def url_decode(encoded_string):
    return urllib.parse.unquote(str(encoded_string))


def decode_and_merge_columns(dataframe):
    # 각 행의 값을 디코딩하여 새로운 열에 추가
    dataframe["QUERY"] = dataframe["QUERY"].apply(url_decode)
    dataframe["BODY"] = dataframe["BODY"].apply(url_decode)

    # + 문자를 공백으로 대체
    dataframe["QUERY"] = dataframe["QUERY"].replace(r"\+", "", regex=True)
    dataframe["BODY"] = dataframe["BODY"].replace(r"\+", "", regex=True)

    return dataframe


def add_tfidf_features(dataframe):
    text_data_test = (
        dataframe["URI"] + " " + dataframe["QUERY"] + " " + dataframe["BODY"]
    )

    # 학습된 TF-IDF 모델 사용
    tfidf_matrix_test = tfidf_vectorizer.transform(text_data_test)

    tfidf_dataframe_test = pd.DataFrame(
        tfidf_matrix_test.toarray(), columns=tfidf_vectorizer.get_feature_names_out()
    )

    dataframe = pd.concat([dataframe, tfidf_dataframe_test], axis=1)
    return dataframe


# 원하는 패턴을 찾는 함수 정의
def find_pattern(dataframe, column_name, target_string):
    # 대소문자를 구분하지 않고 탐지하기 위한 정규 표현식 패턴 설정
    pattern = re.compile(re.escape(target_string) + r"\b", flags=re.IGNORECASE)

    # 데이터프레임의 열을 문자열로 변환한 후 정규 표현식 패턴과 일치하는 문자열 개수를 반환
    return dataframe[column_name].apply(lambda x: len(pattern.findall(str(x))))


def detect_and_aggregate_patterns(dataframe):
    # 'QUERY', 'BODY' 컬럼에서 탐지 문자열들의 빈도수 계산
    for target in target_strings:
        dataframe[f"QUERY_{target}"] = find_pattern(dataframe, "QUERY", target)
        dataframe[f"BODY_{target}"] = find_pattern(dataframe, "BODY", target)
        dataframe[f"URI_{target}"] = find_pattern(dataframe, "URI", target)
        dataframe[f"URI&BODY&QUERY_{target}"] = (
            dataframe[f"QUERY_{target}"]
            + dataframe[f"BODY_{target}"]
            + dataframe[f"URI_{target}"]
        )

    for column in ["URI", "QUERY", "BODY"]:
        # 열의 데이터 타입이 문자열인 경우에만 적용
        dataframe[column] = dataframe[column].str.replace(" ", "")

    # 'QUERY', 'BODY' 컬럼에서 탐지 문자열들의 빈도수 계산
    for target in target_strings_2:
        dataframe[f"QUERY_{target}"] = find_pattern_no_space(dataframe, "QUERY", target)
        dataframe[f"BODY_{target}"] = find_pattern_no_space(dataframe, "BODY", target)
        dataframe[f"URI_{target}"] = find_pattern_no_space(dataframe, "URI", target)
        dataframe[f"URI&BODY&QUERY_{target}"] = (
            dataframe[f"QUERY_{target}"]
            + dataframe[f"BODY_{target}"]
            + dataframe[f"URI_{target}"]
        )
    return dataframe


def add_text_length_features(data):
    data["QUERY_COUNT"] = 0
    data["QUERY_COUNT"] = data["QUERY"].apply(lambda x: len(str(x)))

    data["BODY_COUNT"] = 0
    data["BODY_COUNT"] = data["BODY"].apply(lambda x: len(str(x)))

    return data


def add_one_hot_encoded_features(dataframe):
    encoded_data = one_hot_encoder.transform(dataframe[["PROTOCOL", "METHOD"]])
    encoded_df = pd.DataFrame(
        encoded_data.toarray(),
        columns=one_hot_encoder.get_feature_names_out(["PROTOCOL", "METHOD"]),
    )
    data = pd.concat([dataframe, encoded_df], axis=1)
    return data


def apply_kmeans_clustering(data):
    detect_columns = [col for col in data.columns if (col.startswith("URI&"))]

    # 선택된 컬럼들로 데이터프레임 생성
    data_detect = data[detect_columns]

    # 클러스터 결과를 데이터프레임에 추가
    data["cluster"] = kmeans.predict(data_detect)

    # 'cluster' 컬럼을 문자열로 변환
    data["cluster"] = data["cluster"].astype(str)

    cluster_encoded = cluster_encoder.transform(data[["cluster"]])

    # 5를 곱해서 원핫인코딩된 컬럼들에 적용
    cluster_encoded *= 4

    # 다시 데이터프레임으로 변환
    cluster_columns = [f"cluster_{i}" for i in range(cluster_encoded.shape[1])]
    cluster_df = pd.DataFrame(cluster_encoded, columns=cluster_columns)

    # 기존 데이터프레임과 합치기
    data = pd.concat([data, cluster_df], axis=1)

    # 'cluster' 컬럼과 원핫인코딩된 컬럼 제거
    data = data.drop(columns=["cluster"])

    return data
