import sys

# SHA-1 명세에 정의된 초기 해시 값 (H)
H = [
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
]

# 헬퍼 함수: 32비트 왼쪽 회전
def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def process_chunk(chunk, h):
    """하나의 512비트 청크를 처리하여 해시 값을 갱신"""
    w = [0] * 80
    # 1. 메시지 확장 (Message Schedule)
    for i in range(16):
        w[i] = int.from_bytes(chunk[i*4:i*4+4], 'big')

    for i in range(16, 80):
        w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)

    # 2. 작업 변수 초기화
    a, b, c, d, e = h

    # 3. 압축 함수 (Compression Function) - 80 라운드
    for i in range(80):
        if 0 <= i <= 19:
            f = (b & c) | ((~b) & d)
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:  # 60 <= i <= 79
            f = b ^ c ^ d
            k = 0xCA62C1D6

        temp = (rotl(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        e = d
        d = c
        c = rotl(b, 30)
        b = a
        a = temp

    # 4. 중간 해시 값 갱신
    return [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e])]

def sha1(message: str):
    """
    주어진 문자열의 SHA-1 해시를 라이브러리 없이 계산합니다.
    """
    # 1. 메시지를 바이트로 변환
    m = message.encode('utf-8')
    ml = len(m) * 8  # 메시지 길이 (비트 단위)

    # 2. 패딩 (Padding)
    m += b'\x80'
    while (len(m) * 8) % 512 != 448:
        m += b'\x00'
    m += ml.to_bytes(8, 'big')

    # 3. 초기 해시 값 복사
    h = H[:]

    # 4. 512비트(64바이트) 청크 단위로 처리
    for i in range(0, len(m), 64):
        chunk = m[i:i+64]
        h = process_chunk(chunk, h)

    # 5. 최종 해시 값 생성 (160비트)
    return ''.join(f'{val:08x}' for val in h)

if __name__ == "__main__":
    import hashlib

    if len(sys.argv) > 1:
        text_to_hash = sys.argv[1]
    else:
        print("SHA-1 해시를 계산할 문자열을 입력하세요 (빈 문자열도 가능):")
        text_to_hash = input()

    print(f"\n입력 문자열: '{text_to_hash}'")

    # 직접 구현한 함수로 계산
    manual_hash = sha1(text_to_hash)
    print(f"직접 구현한 SHA-1: {manual_hash}")

    # hashlib 라이브러리로 계산 (검증용)
    library_hash = hashlib.sha1(text_to_hash.encode('utf-8')).hexdigest()
    print(f"라이브러리 SHA-1:   {library_hash}")

    # 결과 비교
    if manual_hash == library_hash:
        print("\n결과 일치: 구현이 올바릅니다.")
    else:
        print("\n결과 불일치: 구현에 오류가 있습니다.")
