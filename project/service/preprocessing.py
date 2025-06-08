import pandas as pd
import joblib
from .utils import (
    find_pattern_no_space,
    url_decode,
    split_payload,
    find_pattern,
    remove_whitespace,
    calculate_sum,
    extract_attack_strings,
)
import warnings

warnings.filterwarnings("ignore")


# 모델 로드
model = joblib.load("pkl/ensemble_model.pkl")
one_hot_encoder = joblib.load("pkl/one_hot_encoder.pkl")
tfidf_vectorizer = joblib.load("pkl/tfidf_model.pkl")
cluster_encoder = joblib.load("pkl/cluster_encoder.pkl")
kmeans = joblib.load("pkl/kmeans_model.pkl")


def preprocessing(df_test):  # 페이로드 한줄

    # 탐지할 문자열 리스트 설정
    target_strings = ["%0D%0A", "%0D", "%0A"]

    # 'QUERY', 'BODY' 컬럼에서 탐지 문자열들의 빈도수 계산
    for target in target_strings:
        df_test[f"QUERY_{target}"] = find_pattern_no_space(df_test, "QUERY", target)
        df_test[f"BODY_{target}"] = find_pattern_no_space(df_test, "BODY", target)
        df_test[f"URI_{target}"] = find_pattern_no_space(df_test, "URI", target)
        df_test[f"URI&BODY&QUERY_{target}"] = (
            df_test[f"QUERY_{target}"]
            + df_test[f"BODY_{target}"]
            + df_test[f"URI_{target}"]
        )

    # 각 행의 값을 디코딩하여 새로운 열에 추가
    df_test["QUERY"] = df_test["QUERY"].apply(url_decode)
    df_test["BODY"] = df_test["BODY"].apply(url_decode)

    # + 문자를 공백으로 대체
    df_test["QUERY"] = df_test["QUERY"].replace(r"\+", "", regex=True)
    df_test["BODY"] = df_test["BODY"].replace(r"\+", "", regex=True)

    # 띄어쓰기 구분해야하는 문자열들
    target_strings = [
        # LdapInjection
        # OS commanding
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
        # PathTransversal
        "etc",
        # Sql Injection
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
        # SSI
        "set",
        "email",
        # Xpathinjection
        # XSS
        # Shell shock
    ]
    target_strings_2 = [
        # LdapInjection
        ")(",
        "(&(",
        "(|(",
        "(||(",
        "*)",
        "*))",
        # OS Commanding
        "&&",
        ";",
        ">",
        "system",
        # PathTransversal
        "./",
        ".\\",
        "../",
        "~/",
        "/../",
        # Sql Injection
        "/**/",
        "‘’=’",
        "=(",
        ";--",
        "1=1",
        # SSI
        "<!--",
        "-->",
        "<!--#",
        "include",
        "cmd",
        # XPath
        "//*",
        "]|//",
        "]|",
        "substring",
        "extractvalue",
        "user",
        "name",
        "|[",
        "1=1",
        # XSS
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
        # SSH
        "{:;};",
        "(){",
        "bash",
        ";}",
    ]
    text_data_test = df_test["URI"] + " " + df_test["QUERY"] + " " + df_test["BODY"]
    tfidf_matrix_test = tfidf_vectorizer.transform(
        text_data_test
    )  # 이미 학습된 TF-IDF 모델 사용
    tfidf_dataframe_test = pd.DataFrame(
        tfidf_matrix_test.toarray(), columns=tfidf_vectorizer.get_feature_names_out()
    )

    df_test = pd.concat([df_test, tfidf_dataframe_test], axis=1)

    # 'QUERY', 'BODY' 컬럼에서 탐지 문자열들의 빈도수 계산
    for target in target_strings:
        df_test[f"QUERY_{target}"] = find_pattern(df_test, "QUERY", target)
        df_test[f"BODY_{target}"] = find_pattern(df_test, "BODY", target)
        df_test[f"URI_{target}"] = find_pattern(df_test, "URI", target)
        df_test[f"URI&BODY&QUERY_{target}"] = (
            df_test[f"QUERY_{target}"]
            + df_test[f"BODY_{target}"]
            + df_test[f"URI_{target}"]
        )

    df_test = remove_whitespace(df_test)

    # 'QUERY', 'BODY' 컬럼에서 탐지 문자열들의 빈도수 계산
    for target in target_strings_2:
        df_test[f"QUERY_{target}"] = find_pattern_no_space(df_test, "QUERY", target)
        df_test[f"BODY_{target}"] = find_pattern_no_space(df_test, "BODY", target)
        df_test[f"URI_{target}"] = find_pattern_no_space(df_test, "URI", target)
        df_test[f"URI&BODY&QUERY_{target}"] = (
            df_test[f"QUERY_{target}"]
            + df_test[f"BODY_{target}"]
            + df_test[f"URI_{target}"]
        )

    encoded_data = one_hot_encoder.transform(df_test[["PROTOCOL", "METHOD"]])
    encoded_df = pd.DataFrame(
        encoded_data.toarray(),
        columns=one_hot_encoder.get_feature_names_out(["PROTOCOL", "METHOD"]),
    )
    data = pd.concat([df_test, encoded_df], axis=1)

    data["QUERY_COUNT"] = 0
    data["QUERY_COUNT"] = data["QUERY"].apply(lambda x: len(str(x)))

    data["BODY_COUNT"] = 0
    data["BODY_COUNT"] = data["BODY"].apply(lambda x: len(str(x)))

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

    col = data.columns.drop(["METHOD", "PROTOCOL", "URI", "QUERY", "BODY"])

    return data[col]


def predict(test_X):
    predictions_test = model.predict(test_X)
    predictions_test = ", ".join(predictions_test)

    probs = model.predict_proba(test_X)

    return predictions_test, probs


def detect_attack_area(test_X, predictions_test):
    attack_sum_uri, attack_sum_query, attack_sum_body = calculate_sum(
        test_X, predictions_test
    )

    return attack_sum_uri, attack_sum_query, attack_sum_body


def detect_attack_string(prediction, test_X):
    uri_attack_array, query_attack_array, body_attack_array = extract_attack_strings(
        prediction, test_X
    )
    return uri_attack_array, query_attack_array, body_attack_array


def convert_dataframe(payload):  # 우리가 정한 데이터셋 컬럼 양식에 맞게 전처리
    # 빈 데이터프레임 생성
    df = pd.DataFrame(columns=["1"])
    # 문자열을 데이터프레임에 추가 (1행 1열에 저장)
    df.loc[0, "1"] = payload
    df_payload = pd.DataFrame()
    df_payload[["METHOD", "URI", "QUERY", "PROTOCOL", "BODY"]] = df.iloc[:, 0].apply(
        lambda x: pd.Series(split_payload(x))
    )

    return df_payload
