import hashlib
import sys

def calculate_sha256(input_string):
    """
    주어진 문자열의 SHA-256 해시 값을 계산하여 반환합니다.
    """
    # 해시 함수는 바이트 데이터를 처리하므로, 문자열을 UTF-8로 인코딩합니다.
    encoded_string = input_string.encode('utf-8')

    # SHA-256 해시 객체를 생성합니다.
    sha256_hash = hashlib.sha256()

    # 인코딩된 문자열을 해시 객체에 업데이트합니다.
    sha256_hash.update(encoded_string)

    # 최종 해시 값을 16진수 문자열 형태로 반환합니다.
    return sha256_hash.hexdigest()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # 명령줄 인자로 문자열을 받은 경우
        text_to_hash = sys.argv[1]
        print(f"입력 문자열: '{text_to_hash}'")
        hashed_value = calculate_sha256(text_to_hash)
        print(f"SHA-256 해시: {hashed_value}")
    else:
        # 인자가 없는 경우 사용자에게 입력 요청
        print("SHA-256 해시를 계산할 문자열을 입력하세요:")
        text_to_hash = input()
        hashed_value = calculate_sha256(text_to_hash)
        print(f"입력 문자열: '{text_to_hash}'")
        print(f"SHA-256 해시: {hashed_value}")
