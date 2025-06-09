from .preprocessing_utils import (
    count_newline_encodings_per_column,
    decode_and_merge_columns,
    add_tfidf_features,
    detect_and_aggregate_patterns,
    add_one_hot_encoded_features,
    add_text_length_features,
    apply_kmeans_clustering,
)


def preprocessing(raw_df):

    # 줄바꿈 인코딩 문자열을 탐지
    df_with_newline_counts = count_newline_encodings_per_column(raw_df)

    # URL 디코딩 및 '+' 문자를 제거
    df_decoded = decode_and_merge_columns(df_with_newline_counts)

    # TF-IDF 모델 적용
    df_tfidf = add_tfidf_features(df_decoded)

    # URI, QUERY, BODY에서 문자열을 탐지
    df_pattern_detected = detect_and_aggregate_patterns(df_tfidf)

    # one hot encoding 수행
    df_one_hot = add_one_hot_encoded_features(df_pattern_detected)

    # 텍스트 길이 관련 피처 추가
    df_with_text_length = add_text_length_features(df_one_hot)

    # 클러스터링 적용
    df_clustered = apply_kmeans_clustering(df_with_text_length)

    selected_cols = df_clustered.columns.drop(
        ["METHOD", "PROTOCOL", "URI", "QUERY", "BODY"]
    )

    return df_clustered[selected_cols]
