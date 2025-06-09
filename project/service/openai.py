import openai


def gpt(payload, prediction):

    # 본인의 OpenAI API 키로 대체하세요
    user_input = payload
    prompt = (
        user_input
        + " 이게 페이로드 값이고 이에 따른 웹 공격 탐지 결과가"
        + prediction
        + "으로 탐지되었는데 그 이유가 무엇지인지 간결하게 5줄 이내로 한국어로 설명해"
    )

    messages = [
        {
            "role": "system",
            "content": "You are a helpful assistant who is good at detailing.",
        },
        {"role": "user", "content": prompt},
    ]
    # OpenAI GPT 모델에 질문 전달
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=messages,
    )

    # GPT 모델의 첫 번째 답변 가져오기
    gpt_response = ""
    for choice in response.choices:
        gpt_response += choice.message.content

        # 대화 확장: 사용자와 어시스턴트 간의 추가 메시지
    messages = [
        {"role": "user", "content": user_input},
        {
            "role": "assistant",
            "content": "페이로드에 대해 탐지된 공격 대처방안에 대해 8줄 이내로 짧게 설명해봐",
        },
    ]

    # 대화 확장을 위해 OpenAI GPT 모델에 추가 질문 전달
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=messages,
    )

    # 어시스턴트의 추가 응답 가져오기
    assistant_response = response.choices[-1].message.content
    # gpt_response = gpt_response.replace('다.', '다.\n')  # 예제: 마침표 뒤에 개행 문자 추가
    # assistant_response = assistant_response.replace('다.', '다.\n')  # 예제: 마침표 뒤에 개행 문자 추가

    return gpt_response, assistant_response
