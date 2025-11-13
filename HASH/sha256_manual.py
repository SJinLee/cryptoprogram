import sys

# SHA-256 명세에 정의된 상수들

# K: 처음 64개 소수의 세제곱근의 소수부 32비트
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# H: 처음 8개 소수의 제곱근의 소수부 32비트 (초기 해시 값)
H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# SHA-256 헬퍼 함수 (비트 연산)
def rotr(x, n):
    """32비트 오른쪽 회전"""
    return (x >> n) | (x << (32 - n)) & 0xFFFFFFFF

def shr(x, n):
    """32비트 오른쪽 시프트"""
    return x >> n

def ch(x, y, z):
    """Choose 함수"""
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    """Majority 함수"""
    return (x & y) ^ (x & z) ^ (y & z)

def sigma0(x):
    """Σ0 함수"""
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def sigma1(x):
    """Σ1 함수"""
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def delta0(x):
    """σ0 함수"""
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

def delta1(x):
    """σ1 함수"""
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)

def process_chunk(chunk, h):
    """하나의 512비트 청크를 처리하여 해시 값을 갱신"""
    w = [0] * 64
    # 1. 메시지 확장 (Message Schedule)
    for i in range(16):
        w[i] = int.from_bytes(chunk[i*4:i*4+4], 'big')

    for i in range(16, 64):
        s0 = delta0(w[i-15])
        s1 = delta1(w[i-2])
        w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF

    # 2. 작업 변수 초기화
    a, b, c, d, e, f, g, hh = h

    # 3. 압축 함수 (Compression Function) - 64 라운드
    for i in range(64):
        S1 = sigma1(e)
        ch_val = ch(e, f, g)
        temp1 = (hh + S1 + ch_val + K[i] + w[i]) & 0xFFFFFFFF
        S0 = sigma0(a)
        maj_val = maj(a, b, c)
        temp2 = (S0 + maj_val) & 0xFFFFFFFF

        hh = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF

    # 4. 중간 해시 값 갱신
    return [(x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e, f, g, hh])]

def sha256(message: str):
    """
    주어진 문자열의 SHA-256 해시를 라이브러리 없이 계산합니다.
    """
    # 1. 메시지를 바이트로 변환
    m = message.encode('utf-8')
    ml = len(m) * 8  # 메시지 길이 (비트 단위)

    # 2. 패딩 (Padding)
    # 메시지 뒤에 '1' 비트 추가 (10000000 -> 0x80)
    m += b'\x80'
    # 512비트(64바이트) 블록 경계에 맞게 '0' 비트 추가
    while (len(m) * 8) % 512 != 448:
        m += b'\x00'
    # 마지막 64비트에 원본 메시지 길이를 big-endian으로 추가
    m += ml.to_bytes(8, 'big')

    # 3. 초기 해시 값 복사
    h = H[:]

    # 4. 512비트(64바이트) 청크 단위로 처리
    for i in range(0, len(m), 64):
        chunk = m[i:i+64]
        h = process_chunk(chunk, h)

    # 5. 최종 해시 값 생성
    return ''.join(f'{val:08x}' for val in h)

if __name__ == "__main__":
    import hashlib

    if len(sys.argv) > 1:
        text_to_hash = sys.argv[1]
    else:
        print("SHA-256 해시를 계산할 문자열을 입력하세요 (빈 문자열도 가능):")
        text_to_hash = input()

    print(f"\n입력 문자열: '{text_to_hash}'")

    # 직접 구현한 함수로 계산
    manual_hash = sha256(text_to_hash)
    print(f"직접 구현한 SHA-256: {manual_hash}")

    # hashlib 라이브러리로 계산 (검증용)
    library_hash = hashlib.sha256(text_to_hash.encode('utf-8')).hexdigest()
    print(f"라이브러리 SHA-256:   {library_hash}")

    # 결과 비교
    if manual_hash == library_hash:
        print("\n결과 일치: 구현이 올바릅니다.")
    else:
        print("\n결과 불일치: 구현에 오류가 있습니다.")
