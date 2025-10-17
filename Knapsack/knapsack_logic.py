import random

def power(y, k, p):
    """(y^k) mod p 계산"""
    return pow(y, k, p)

def extended_gcd(a, b):
    """확장 유클리드 알고리즘"""
    if a == 0:
        return b, 0, 1
    d, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return d, x, y

def mod_inverse(x, p):
    """x^(-1) mod p 계산"""
    d, x1, y1 = extended_gcd(x, p)
    if d != 1:
        raise Exception('모듈러 역원이 존재하지 않습니다.')
    return x1 % p

def is_prime(n, k=5):
    """Miller-Rabin 소수 판별법"""
    if n < 2: return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
        if n == p: return True
        if n % p == 0: return False
    s, d = 0, n - 1
    while d % 2 == 0:
        s, d = s + 1, d // 2
    for _ in range(k):
        a = random.randint(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

def find_next_prime(n):
    """n보다 큰 다음 소수를 찾음"""
    if n % 2 == 0: n += 1
    else: n += 2
    while not is_prime(n):
        n += 2
    return n

def create_random_private_key(seq_len=16):
    """무작위로 개인키 (w, p, y) 생성"""
    w = []
    current_sum = 0
    for _ in range(seq_len):
        next_val = random.randint(current_sum + 1, current_sum + 10)
        w.append(next_val)
        current_sum += next_val
    
    p = find_next_prime(current_sum)
    y = random.randint(2, p - 1)
    return w, p, y

def generate_keys(w, p, y):
    """개인키와 공개키 생성"""
    if sum(w) >= p:
        raise ValueError("p는 w 수열의 합보다 커야 합니다.")

    beta = [(i * y) % p for i in w]
    private_key = (w, p, y)
    public_key = beta
    return private_key, public_key

def encrypt(public_key, plaintext_int):
    """숫자 평문을 암호화"""
    key_len = len(public_key)
    max_val = (2**key_len) - 1
    if not (0 <= plaintext_int <= max_val):
        raise ValueError(f"평문은 0과 {max_val} 사이의 숫자여야 합니다.")

    binary_plain = format(plaintext_int, f'0{key_len}b')
    
    c = sum(int(bit) * key_part for bit, key_part in zip(binary_plain, public_key))
    return c, binary_plain

def decrypt(private_key, ciphertext):
    """암호문을 복호화하여 숫자로 반환"""
    w, p, y = private_key
    y_inv = mod_inverse(y, p)
    c_prime = (ciphertext * y_inv) % p

    binary_plain_list = ['0'] * len(w)
    for i in range(len(w) - 1, -1, -1):
        if c_prime >= w[i]:
            c_prime -= w[i]
            binary_plain_list[i] = '1'
    
    binary_str = "".join(binary_plain_list)
    decrypted_int = int(binary_str, 2)
    return decrypted_int
