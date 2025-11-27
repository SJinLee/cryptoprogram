import random
import hashlib

# --- Cryptographic Primitives ---

def get_correct_primes():
    """Returns a valid pair of primes (p, q) where q is a prime factor of p-1."""
    # Using smaller, but valid, numbers for demonstration.
    q = 101  # A prime number
    # We need to find a prime p such that p = k*q + 1 for some integer k.
    # For k=6, p = 6*101 + 1 = 607, which is a prime number.
    p = 607
    return p, q

def find_generator(p, q):
    """pとqに対するジェネレータgを見つけます。"""
    while True:
        h = random.randrange(2, p - 1)
        g = pow(h, (p - 1) // q, p)
        if g != 1:
            return g

# --- Protocol Implementations ---

class SchnorrProtocol:
    """Schnorr 개인 식별 프로토콜 테스트 클래스"""
    def __init__(self):
        print("--- Schnorr 프로토콜 초기화 ---")
        self.p, self.q = get_correct_primes()
        self.g = find_generator(self.p, self.q)
        print(f"p(소수): {self.p}")
        print(f"q(소수): {self.q}")
        print(f"g(생성자): {self.g}\n")

    def run_test(self):
        print("--- Schnorr 프로토콜 테스트 시작 ---")
        # 1. 키 생성
        x = random.randrange(1, self.q)  # 개인키
        y = pow(self.g, x, self.p)      # 공개키
        print(f"[1. 키 생성]")
        print(f"  - 개인키(x): {x}")
        print(f"  - 공개키(y): {y}\n")

        # --- 상호작용 프로토콜 시작 ---
        print("[2. 프로토콜 실행]")
        # 증명자(Prover): 약속 (Commitment)
        k = random.randrange(1, self.q)
        r = pow(self.g, k, self.p)
        print(f"  - 증명자: 임의의 k 선택, r = g^k mod p 계산")
        print(f"    -> r = {r} (검증자에게 전송)\n")

        # 검증자(Verifier): 질문 (Challenge)
        e = random.randrange(1, self.q)
        print(f"  - 검증자: 임의의 e 선택")
        print(f"    -> e = {e} (증명자에게 전송)\n")

        # 증명자(Prover): 응답 (Response)
        s = (k + e * x) % self.q
        print(f"  - 증명자: s = k + e*x mod q 계산")
        print(f"    -> s = {s} (검증자에게 전송)\n")

        # --- 검증 ---
        print("[3. 검증]")
        lhs = pow(self.g, s, self.p)
        rhs = (r * pow(y, e, self.p)) % self.p
        
        print(f"  - 검증자: g^s mod p == (r * y^e) mod p 인지 확인")
        print(f"    - 좌변 (g^s): {lhs}")
        print(f"    - 우변 (r * y^e): {rhs}")

        if lhs == rhs:
            print("\n[결과] 검증 성공! 증명자가 올바른 개인키를 소유하고 있습니다.\n")
            return True
        else:
            print("\n[결과] 검증 실패!\n")
            return False

class OkamotoProtocol:
    """Okamoto 개인 식별 프로토콜 테스트 클래스"""
    def __init__(self):
        print("--- Okamoto 프로토콜 초기화 ---")
        self.p, self.q = get_correct_primes()
        self.g1 = find_generator(self.p, self.q)
        self.g2 = find_generator(self.p, self.q)
        while self.g1 == self.g2: # g1과 g2는 달라야 합니다.
            self.g2 = find_generator(self.p, self.q)
        
        print(f"p(소수): {self.p}")
        print(f"q(소수): {self.q}")
        print(f"g1(생성자1): {self.g1}")
        print(f"g2(생성자2): {self.g2}\n")

    def run_test(self):
        print("--- Okamoto 프로토콜 테스트 시작 ---")
        # 1. 키 생성
        s1 = random.randrange(1, self.q) # 개인키 1
        s2 = random.randrange(1, self.q) # 개인키 2
        v = (pow(self.g1, s1, self.p) * pow(self.g2, s2, self.p)) % self.p # 공개키
        print(f"[1. 키 생성]")
        print(f"  - 개인키(s1): {s1}")
        print(f"  - 개인키(s2): {s2}")
        print(f"  - 공개키(v): {v}\n")

        # --- 상호작용 프로토콜 시작 ---
        print("[2. 프로토콜 실행]")
        # 증명자(Prover): 약속 (Commitment)
        r1 = random.randrange(1, self.q)
        r2 = random.randrange(1, self.q)
        x_val = (pow(self.g1, r1, self.p) * pow(self.g2, r2, self.p)) % self.p
        print(f"  - 증명자: 임의의 (r1, r2) 선택, x = g1^r1 * g2^r2 mod p 계산")
        print(f"    -> x = {x_val} (검증자에게 전송)\n")

        # 검증자(Verifier): 질문 (Challenge)
        c = random.randrange(1, self.q)
        print(f"  - 검증자: 임의의 c 선택")
        print(f"    -> c = {c} (증명자에게 전송)\n")

        # 증명자(Prover): 응답 (Response)
        y1 = (r1 + c * s1) % self.q
        y2 = (r2 + c * s2) % self.q
        print(f"  - 증명자: y1 = r1 + c*s1, y2 = r2 + c*s2 mod q 계산")
        print(f"    -> (y1, y2) = ({y1}, {y2}) (검증자에게 전송)\n")

        # --- 검증 ---
        print("[3. 검증]")
        lhs = (pow(self.g1, y1, self.p) * pow(self.g2, y2, self.p)) % self.p
        rhs = (x_val * pow(v, c, self.p)) % self.p

        print(f"  - 검증자: g1^y1 * g2^y2 mod p == (x * v^c) mod p 인지 확인")
        print(f"    - 좌변 (g1^y1 * g2^y2): {lhs}")
        print(f"    - 우변 (x * v^c): {rhs}")

        if lhs == rhs:
            print("\n[결과] 검증 성공! 증명자가 올바른 개인키를 소유하고 있습니다.\n")
            return True
        else:
            print("\n[결과] 검증 실패!\n")
            return False

# --- 메인 실행 ---
if __name__ == "__main__":
    print("========================================\n")
    schnorr_test = SchnorrProtocol()
    schnorr_test.run_test()
    print("========================================\n")
    okamoto_test = OkamotoProtocol()
    okamoto_test.run_test()
    print("========================================\n")
