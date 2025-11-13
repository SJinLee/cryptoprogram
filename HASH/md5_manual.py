import sys
import math

# MD5 명세(RFC 1321)에 정의된 상수들

# 라운드별 왼쪽 회전 비트 수
S = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
]

# T: sin 값으로 생성된 64개의 32비트 상수
T = [int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

# 초기 버퍼 값 (A, B, C, D)
init_buffers = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

# 헬퍼 함수: 32비트 왼쪽 회전
def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def process_chunk(chunk, buffers):
    """하나의 512비트 청크를 처리하여 버퍼 값을 갱신"""
    a, b, c, d = buffers

    # 512비트 청크를 16개의 32비트 워드로 분리 (리틀 엔디안)
    m = [int.from_bytes(chunk[i*4:i*4+4], 'little') for i in range(16)]

    # 64 라운드 압축 함수
    for i in range(64):
        if 0 <= i <= 15:
            f = (b & c) | ((~b) & d)
            g = i
        elif 16 <= i <= 31:
            f = (d & b) | ((~d) & c)
            g = (5 * i + 1) % 16
        elif 32 <= i <= 47:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:  # 48 <= i <= 63
            f = c ^ (b | (~d))
            g = (7 * i) % 16
        
        f = (f + a + T[i] + m[g]) & 0xFFFFFFFF
        a = d
        d = c
        c = b
        b = (b + rotl(f, S[i])) & 0xFFFFFFFF

    # 중간 버퍼 값 갱신
    return [(x + y) & 0xFFFFFFFF for x, y in zip(buffers, [a, b, c, d])]

def md5(message: str):
    """
    주어진 문자열의 MD5 해시를 라이브러리 없이 계산합니다.
    """
    # 1. 메시지를 바이트로 변환
    m = message.encode('utf-8')
    ml = len(m) * 8

    # 2. 패딩
    m += b'\x80'
    while (len(m) * 8) % 512 != 448:
        m += b'\x00'
    # 길이를 64비트 리틀 엔디안으로 추가
    m += ml.to_bytes(8, 'little')

    # 3. 버퍼 초기화
    buffers = init_buffers[:]

    # 4. 512비트(64바이트) 청크 단위로 처리
    for i in range(0, len(m), 64):
        chunk = m[i:i+64]
        buffers = process_chunk(chunk, buffers)

    # 5. 최종 해시 값 생성 (리틀 엔디안으로 합치기)
    result = b''
    for val in buffers:
        result += val.to_bytes(4, 'little')
        
    return result.hex()

if __name__ == "__main__":
    import hashlib

    if len(sys.argv) > 1:
        text_to_hash = sys.argv[1]
    else:
        print("MD5 해시를 계산할 문자열을 입력하세요 (빈 문자열도 가능):")
        text_to_hash = input()

    print(f"\n입력 문자열: '{text_to_hash}'")

    # 직접 구현한 함수로 계산
    manual_hash = md5(text_to_hash)
    print(f"직접 구현한 MD5: {manual_hash}")

    # hashlib 라이브러리로 계산 (검증용)
    library_hash = hashlib.md5(text_to_hash.encode('utf-8')).hexdigest()
    print(f"라이브러리 MD5:   {library_hash}")

    # 결과 비교
    if manual_hash == library_hash:
        print("\n결과 일치: 구현이 올바릅니다.")
    else:
        print("\n결과 불일치: 구현에 오류가 있습니다.")
