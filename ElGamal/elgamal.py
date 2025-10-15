import random
import math

def is_prime(n, k=5):
    """Miller-Rabin 소수 판별법"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """지정된 비트 수의 소수를 생성"""
    while True:
        p = random.getrandbits(bits)
        # 홀수로 만들고, 기본적인 소수들로 나누어지지 않는지 확인
        p |= (1 << bits - 1) | 1
        if is_prime(p):
            return p

def gcd(a, b):
    """유클리드 호제법으로 최대공약수 계산"""
    while b != 0:
        a, b = b, a % b
    return a

def power(a, b, c):
    """모듈러 거듭제곱 (a^b mod c)"""
    return pow(a, b, c)

def mod_inverse(a, m):
    """모듈러 곱셈 역원 계산"""
    return pow(a, -1, m)

def find_primitive_root(p):
    """소수 p의 원시근 찾기"""
    if not is_prime(p):
        return -1
    
    phi = p - 1
    factors = set()
    n = phi
    i = 2
    while i * i <= n:
        if n % i == 0:
            factors.add(i)
            while n % i == 0:
                n //= i
        i += 1
    if n > 1:
        factors.add(n)

    for g in range(2, p):
        is_primitive = True
        for factor in factors:
            if power(g, phi // factor, p) == 1:
                is_primitive = False
                break
        if is_primitive:
            return g
    return -1

def generate_keys(bits=256):
    """ElGamal 키 생성 (공개키, 개인키)"""
    p = generate_prime(bits)
    g = find_primitive_root(p)
    # g가 -1이면 원시근을 못찾은 경우, 다시 시도
    while g == -1:
        p = generate_prime(bits)
        g = find_primitive_root(p)
        
    x = random.randint(2, p - 2) # Private key
    y = power(g, x, p) # Public key component
    
    # 공개키: (p, g, y), 개인키: x
    return {
        'public_key': {'p': p, 'g': g, 'y': y},
        'private_key': {'x': x}
    }

def encrypt(msg, p, g, y, k=None):
    """ElGamal 암호화"""
    # msg는 정수라고 가정
    if k is None or k == 0:
        k = random.randint(2, p - 2)
    c1 = power(g, k, p)
    c2 = (msg * power(y, k, p)) % p
    return c1, c2

def decrypt(c1, c2, x, p):
    """ElGamal 복호화"""
    s = power(c1, x, p)
    s_inv = mod_inverse(s, p)
    msg = (c2 * s_inv) % p
    return msg
