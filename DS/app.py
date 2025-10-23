from flask import Flask, render_template, request, session
import math
import random
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key_here' # Replace with a strong secret key

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return (x % m + m) % m

def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(math.sqrt(num)) + 1):
        if num % i == 0:
            return False
    return True

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def get_prime_factors(n):
    factors = set()
    d = 2
    temp = n
    while d * d <= temp:
        if temp % d == 0:
            factors.add(d)
            while temp % d == 0:
                temp //= d
        d += 1
    if temp > 1:
        factors.add(temp)
    return list(factors)

def find_primitive_root(p):
    if not is_prime(p):
        return None
    if p == 2: return 1
    if p == 3: return 2

    phi = p - 1
    factors = get_prime_factors(phi)

    for g in range(2, p):
        is_primitive = True
        for factor in factors:
            if pow(g, phi // factor, p) == 1:
                is_primitive = False
                break
        if is_primitive:
            return g
    return None

def generate_random_prime(min_val, max_val):
    while True:
        num = random.randint(min_val, max_val)
        if is_prime(num):
            return num

# DSA specific helper functions
def generate_dsa_params(L, N):
    # L is the length of prime p (e.g., 1024, 2048)
    # N is the length of prime q (e.g., 160, 256)
    # For simplicity, we'll use smaller values for demonstration
    # In a real scenario, these would be much larger and generated securely

    # Find a prime q of N bits
    q = generate_random_prime(2** (N-1), 2**N - 1)
    if q is None: return None, None, None

    # Find a prime p of L bits such that q divides p-1
    while True:
        k = random.randint(2**(L-N-1), 2**(L-N) - 1)
        p = k * q + 1
        if is_prime(p):
            break
    
    # Find a generator g
    h = random.randint(2, p - 2)
    g = pow(h, (p - 1) // q, p)
    while g == 1:
        h = random.randint(2, p - 2)
        g = pow(h, (p - 1) // q, p)

    return p, q, g


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/overview')
def overview():
    return render_template('overview.html')

@app.route('/rsa_signature', methods=['GET', 'POST'])
def rsa_signature():
    rsa_p, rsa_q, rsa_n, rsa_e, rsa_d, rsa_key_error = None, None, None, None, None, None
    rsa_message_sign, rsa_d_sign, rsa_n_sign, rsa_signature_result, rsa_sign_error = None, None, None, None, None
    rsa_message_verify, rsa_signature_verify, rsa_e_verify, rsa_n_verify, rsa_verification_result, rsa_verify_error = None, None, None, None, None, None

    # Retrieve stored keys from session if available
    if 'rsa_n' in session:
        rsa_n = session['rsa_n']
    if 'rsa_e' in session:
        rsa_e = session['rsa_e']
    if 'rsa_d' in session:
        rsa_d = session['rsa_d']

    if request.method == 'POST':
        rsa_operation = request.form.get('rsa_operation')

        if rsa_operation == 'generate_keys':
            try:
                rsa_p = int(request.form.get('p'))
                rsa_q = int(request.form.get('q'))

                if not is_prime(rsa_p) or not is_prime(rsa_q):
                    rsa_key_error = "p와 q는 소수여야 합니다."
                elif rsa_p == rsa_q:
                    rsa_key_error = "p와 q는 다른 소수여야 합니다."
                else:
                    rsa_n = rsa_p * rsa_q
                    phi_n = (rsa_p - 1) * (rsa_q - 1)

                    # Choose e
                    for i in range(2, phi_n):
                        if gcd(i, phi_n) == 1:
                            rsa_e = i
                            break
                    
                    if rsa_e is None:
                        rsa_key_error = "적절한 공개 지수 e를 찾을 수 없습니다."
                    else:
                        rsa_d = mod_inverse(rsa_e, phi_n)
                        if rsa_d is None:
                            rsa_key_error = "개인 지수 d를 계산할 수 없습니다."
                        else:
                            # Store generated keys in session
                            session['rsa_n'] = rsa_n
                            session['rsa_e'] = rsa_e
                            session['rsa_d'] = rsa_d

            except ValueError:
                rsa_key_error = "유효한 숫자를 입력해주세요."

        elif rsa_operation == 'sign':
            try:
                rsa_message_sign = request.form.get('message')
                rsa_d_sign = int(request.form.get('d'))
                rsa_n_sign = int(request.form.get('n'))

                # Use SHA-256 for hashing
                h = int(hashlib.sha256(rsa_message_sign.encode()).hexdigest(), 16) % rsa_n_sign
                rsa_signature_result = pow(h, rsa_d_sign, rsa_n_sign)

            except ValueError:
                rsa_sign_error = "유효한 숫자를 입력해주세요."

        elif rsa_operation == 'verify':
            try:
                rsa_message_verify = request.form.get('message')
                rsa_signature_verify = int(request.form.get('signature'))
                rsa_e_verify = int(request.form.get('e'))
                rsa_n_verify = int(request.form.get('n'))

                # Use SHA-256 for hashing
                h_prime = int(hashlib.sha256(rsa_message_verify.encode()).hexdigest(), 16) % rsa_n_verify
                h_from_signature = pow(rsa_signature_verify, rsa_e_verify, rsa_n_verify)

                if h_prime == h_from_signature:
                    rsa_verification_result = "서명 유효함"
                else:
                    rsa_verification_result = "서명 유효하지 않음"

            except ValueError:
                rsa_verify_error = "유효한 숫자를 입력해주세요."

    return render_template('rsa_signature.html',
                           rsa_p=rsa_p, rsa_q=rsa_q, rsa_n=rsa_n, rsa_e=rsa_e, rsa_d=rsa_d, rsa_key_error=rsa_key_error,
                           rsa_message_sign=rsa_message_sign, rsa_d_sign=rsa_d_sign, rsa_n_sign=rsa_n_sign, rsa_signature_result=rsa_signature_result, rsa_sign_error=rsa_sign_error,
                           rsa_message_verify=rsa_message_verify, rsa_signature_verify=rsa_signature_verify, rsa_e_verify=rsa_e_verify, rsa_n_verify=rsa_n_verify, rsa_verification_result=rsa_verification_result, rsa_verify_error=rsa_verify_error,
                           session_rsa_n=session.get('rsa_n'), session_rsa_e=session.get('rsa_e'), session_rsa_d=session.get('rsa_d'))

@app.route('/elgamal_signature', methods=['GET', 'POST'])
def elgamal_signature():
    elgamal_p, elgamal_g, elgamal_x, elgamal_y, elgamal_key_error = None, None, None, None, None
    elgamal_message_sign, elgamal_p_sign, elgamal_g_sign, elgamal_x_sign, elgamal_k_sign, elgamal_r_result, elgamal_s_result, elgamal_sign_error = None, None, None, None, None, None, None, None
    elgamal_message_verify, elgamal_r_verify, elgamal_s_verify, elgamal_p_verify, elgamal_g_verify, elgamal_y_verify, elgamal_verification_result, elgamal_verify_error = None, None, None, None, None, None, None, None

    # Retrieve stored keys from session if available
    if 'elgamal_p' in session:
        elgamal_p = session['elgamal_p']
    if 'elgamal_g' in session:
        elgamal_g = session['elgamal_g']
    if 'elgamal_x' in session:
        elgamal_x = session['elgamal_x']
    if 'elgamal_y' in session:
        elgamal_y = session['elgamal_y']

    if request.method == 'POST':
        elgamal_operation = request.form.get('elgamal_operation')

        if elgamal_operation == 'generate_keys':
            try:
                elgamal_p = int(request.form.get('p'))
                elgamal_g = int(request.form.get('g'))
                elgamal_x = int(request.form.get('x'))

                if not is_prime(elgamal_p):
                    elgamal_key_error = "p는 소수여야 합니다."
                elif not (1 < elgamal_g < elgamal_p):
                    elgamal_key_error = "g는 1 < g < p를 만족해야 합니다."
                elif not (1 < elgamal_x < elgamal_p - 1):
                    elgamal_key_error = "x는 1 < x < p-1을 만족해야 합니다."
                else:
                    elgamal_y = pow(elgamal_g, elgamal_x, elgamal_p)
                    # Store generated keys in session
                    session['elgamal_p'] = elgamal_p
                    session['elgamal_g'] = elgamal_g
                    session['elgamal_x'] = elgamal_x
                    session['elgamal_y'] = elgamal_y

            except ValueError:
                elgamal_key_error = "유효한 숫자를 입력해주세요."

        elif elgamal_operation == 'sign':
            try:
                elgamal_message_sign = request.form.get('message')
                elgamal_p_sign = int(request.form.get('p'))
                elgamal_g_sign = int(request.form.get('g'))
                elgamal_x_sign = int(request.form.get('x'))
                elgamal_k_sign = int(request.form.get('k'))

                if not is_prime(elgamal_p_sign):
                    elgamal_sign_error = "p는 소수여야 합니다."
                elif not (1 < elgamal_k_sign < elgamal_p_sign - 1) or gcd(elgamal_k_sign, elgamal_p_sign - 1) != 1:
                    elgamal_sign_error = "k는 1 < k < p-1 이고 gcd(k, p-1) = 1을 만족하는 무작위 정수여야 합니다."
                else:
                    h = int(hashlib.sha256(elgamal_message_sign.encode()).hexdigest(), 16) % elgamal_p_sign # Use SHA-256
                    elgamal_r_result = pow(elgamal_g_sign, elgamal_k_sign, elgamal_p_sign)
                    k_inv = mod_inverse(elgamal_k_sign, elgamal_p_sign - 1)
                    if k_inv is None:
                        elgamal_sign_error = "k의 모듈러 역원을 찾을 수 없습니다."
                    else:
                        elgamal_s_result = (h - elgamal_x_sign * elgamal_r_result) * k_inv % (elgamal_p_sign - 1)

            except ValueError:
                elgamal_sign_error = "유효한 숫자를 입력해주세요."

        elif elgamal_operation == 'verify':
            try:
                elgamal_message_verify = request.form.get('message')
                elgamal_r_verify = int(request.form.get('r'))
                elgamal_s_verify = int(request.form.get('s'))
                elgamal_p_verify = int(request.form.get('p'))
                elgamal_g_verify = int(request.form.get('g'))
                elgamal_y_verify = int(request.form.get('y'))

                h_prime = int(hashlib.sha256(elgamal_message_verify.encode()).hexdigest(), 16) % elgamal_p_verify # Use SHA-256

                v1 = (pow(elgamal_y_verify, elgamal_r_verify, elgamal_p_verify) * pow(elgamal_r_verify, elgamal_s_verify, elgamal_p_verify)) % elgamal_p_verify
                v2 = pow(elgamal_g_verify, h_prime, elgamal_p_verify)

                if v1 == v2:
                    elgamal_verification_result = "서명 유효함"
                else:
                    elgamal_verification_result = "서명 유효하지 않음"

            except ValueError:
                elgamal_verify_error = "유효한 숫자를 입력해주세요."

    return render_template('elgamal_signature.html',
                           elgamal_p=elgamal_p, elgamal_g=elgamal_g, elgamal_x=elgamal_x, elgamal_y=elgamal_y, elgamal_key_error=elgamal_key_error,
                           elgamal_message_sign=elgamal_message_sign, elgamal_p_sign=elgamal_p_sign, elgamal_g_sign=elgamal_g_sign, elgamal_x_sign=elgamal_x_sign, elgamal_k_sign=elgamal_k_sign, elgamal_r_result=elgamal_r_result, elgamal_s_result=elgamal_s_result, elgamal_sign_error=elgamal_sign_error,
                           elgamal_message_verify=elgamal_message_verify, elgamal_r_verify=elgamal_r_verify, elgamal_s_verify=elgamal_s_verify, elgamal_p_verify=elgamal_p_verify, elgamal_g_verify=elgamal_g_verify, elgamal_y_verify=elgamal_y_verify, elgamal_verification_result=elgamal_verification_result, elgamal_verify_error=elgamal_verify_error,
                           session_elgamal_p=session.get('elgamal_p'), session_elgamal_g=session.get('elgamal_g'), session_elgamal_x=session.get('elgamal_x'), session_elgamal_y=session.get('elgamal_y'))

@app.route('/dss_signature', methods=['GET', 'POST'])
def dss_signature():
    dsa_p, dsa_q, dsa_g, dsa_x, dsa_y, dsa_key_error = None, None, None, None, None, None
    dsa_message_sign, dsa_p_sign, dsa_q_sign, dsa_g_sign, dsa_x_sign, dsa_k_sign, dsa_r_result, dsa_s_result, dsa_sign_error = None, None, None, None, None, None, None, None, None
    dsa_message_verify, dsa_p_verify, dsa_q_verify, dsa_g_verify, dsa_y_verify, dsa_r_verify, dsa_s_verify, dsa_verification_result, dsa_verify_error = None, None, None, None, None, None, None, None, None

    # Retrieve stored keys from session if available
    if 'dsa_p' in session:
        dsa_p = session['dsa_p']
    if 'dsa_q' in session:
        dsa_q = session['dsa_q']
    if 'dsa_g' in session:
        dsa_g = session['dsa_g']
    if 'dsa_x' in session:
        dsa_x = session['dsa_x']
    if 'dsa_y' in session:
        dsa_y = session['dsa_y']

    if request.method == 'POST':
        dsa_operation = request.form.get('dsa_operation')

        if dsa_operation == 'generate_keys':
            try:
                # For simplicity, we'll generate small primes for demonstration
                # In a real scenario, L and N would be much larger (e.g., L=1024, N=160)
                L = int(request.form.get('L', 512)) # Bit length for p
                N = int(request.form.get('N', 160)) # Bit length for q

                dsa_p, dsa_q, dsa_g = generate_dsa_params(L, N)

                if dsa_p is None or dsa_q is None or dsa_g is None:
                    dsa_key_error = "DSA 파라미터 (p, q, g) 생성에 실패했습니다. 더 큰 범위나 다른 값을 시도해보세요."
                else:
                    # Generate private key x
                    dsa_x = random.randint(1, dsa_q - 1)
                    # Calculate public key y
                    dsa_y = pow(dsa_g, dsa_x, dsa_p)

                    session['dsa_p'] = dsa_p
                    session['dsa_q'] = dsa_q
                    session['dsa_g'] = dsa_g
                    session['dsa_x'] = dsa_x
                    session['dsa_y'] = dsa_y

            except ValueError:
                dsa_key_error = "유효한 숫자를 입력해주세요."

        elif dsa_operation == 'sign':
            try:
                dsa_message_sign = request.form.get('message')
                dsa_p_sign = int(request.form.get('p'))
                dsa_q_sign = int(request.form.get('q'))
                dsa_g_sign = int(request.form.get('g'))
                dsa_x_sign = int(request.form.get('x'))
                dsa_k_sign = int(request.form.get('k'))

                if not (0 < dsa_k_sign < dsa_q_sign) or gcd(dsa_k_sign, dsa_q_sign) != 1:
                    dsa_sign_error = "k는 0 < k < q 이고 gcd(k, q) = 1을 만족하는 무작위 정수여야 합니다."
                else:
                    h = int(hashlib.sha256(dsa_message_sign.encode()).hexdigest(), 16)
                    h = h % dsa_q # Hash value modulo q

                    r = pow(dsa_g_sign, dsa_k_sign, dsa_p_sign) % dsa_q
                    if r == 0:
                        dsa_sign_error = "r이 0이 되어 서명에 실패했습니다. 다른 k 값을 시도해보세요."
                    else:
                        k_inv = mod_inverse(dsa_k_sign, dsa_q_sign)
                        if k_inv is None:
                            dsa_sign_error = "k의 모듈러 역원을 찾을 수 없습니다."
                        else:
                            s = (k_inv * (h + dsa_x_sign * r)) % dsa_q
                            if s == 0:
                                dsa_sign_error = "s가 0이 되어 서명에 실패했습니다. 다른 k 값을 시도해보세요."
                            else:
                                dsa_r_result = r
                                dsa_s_result = s

            except ValueError:
                dsa_sign_error = "유효한 숫자를 입력해주세요."

        elif dsa_operation == 'verify':
            try:
                dsa_message_verify = request.form.get('message')
                dsa_p_verify = int(request.form.get('p'))
                dsa_q_verify = int(request.form.get('q'))
                dsa_g_verify = int(request.form.get('g'))
                dsa_y_verify = int(request.form.get('y'))
                dsa_r_verify = int(request.form.get('r'))
                dsa_s_verify = int(request.form.get('s'))

                if not (0 < dsa_r_verify < dsa_q_verify) or not (0 < dsa_s_verify < dsa_q_verify):
                    dsa_verify_error = "서명 (r, s) 값이 유효하지 않습니다. (0 < r, s < q)"
                else:
                    h_prime = int(hashlib.sha256(dsa_message_verify.encode()).hexdigest(), 16)
                    h_prime = h_prime % dsa_q # Hash value modulo q

                    w = mod_inverse(dsa_s_verify, dsa_q_verify)
                    if w is None:
                        dsa_verify_error = "s의 모듈러 역원을 찾을 수 없습니다."
                    else:
                        u1 = (h_prime * w) % dsa_q_verify
                        u2 = (dsa_r_verify * w) % dsa_q_verify
                        v = (pow(dsa_g_verify, u1, dsa_p_verify) * pow(dsa_y_verify, u2, dsa_p_verify)) % dsa_p_verify % dsa_q_verify

                        if v == dsa_r_verify:
                            dsa_verification_result = "서명 유효함"
                        else:
                            dsa_verification_result = "서명 유효하지 않음"

            except ValueError:
                dsa_verify_error = "유효한 숫자를 입력해주세요."

    return render_template('dss_signature.html',
                           dsa_p=dsa_p, dsa_q=dsa_q, dsa_g=dsa_g, dsa_x=dsa_x, dsa_y=dsa_y, dsa_key_error=dsa_key_error,
                           dsa_message_sign=dsa_message_sign, dsa_p_sign=dsa_p_sign, dsa_q_sign=dsa_q_sign, dsa_g_sign=dsa_g_sign, dsa_x_sign=dsa_x_sign, dsa_k_sign=dsa_k_sign, dsa_r_result=dsa_r_result, dsa_s_result=dsa_s_result, dsa_sign_error=dsa_sign_error,
                           dsa_message_verify=dsa_message_verify, dsa_p_verify=dsa_p_verify, dsa_q_verify=dsa_q_verify, dsa_g_verify=dsa_g_verify, dsa_y_verify=dsa_y_verify, dsa_r_verify=dsa_r_verify, dsa_s_verify=dsa_s_verify, dsa_verification_result=dsa_verification_result, dsa_verify_error=dsa_verify_error,
                           session_dsa_p=session.get('dsa_p'), session_dsa_q=session.get('dsa_q'), session_dsa_g=session.get('dsa_g'), session_dsa_x=session.get('dsa_x'), session_dsa_y=session.get('dsa_y'))

@app.route('/nyberg_rueppel', methods=['GET', 'POST'])
def nyberg_rueppel():
    nr_p, nr_g, nr_x, nr_y, nr_key_error = None, None, None, None, None
    nr_message_sign, nr_p_sign, nr_g_sign, nr_x_sign, nr_k_sign, nr_r_result, nr_s_result, nr_sign_error = None, None, None, None, None, None, None, None
    nr_message_verify, nr_r_verify, nr_s_verify, nr_p_verify, nr_g_verify, nr_y_verify, nr_verification_result, nr_verify_error = None, None, None, None, None, None, None, None

    # Retrieve stored keys from session if available
    if 'nr_p' in session:
        nr_p = session['nr_p']
    if 'nr_g' in session:
        nr_g = session['nr_g']
    if 'nr_x' in session:
        nr_x = session['nr_x']
    if 'nr_y' in session:
        nr_y = session['nr_y']

    if request.method == 'POST':
        nr_operation = request.form.get('nr_operation')

        if nr_operation == 'generate_keys':
            try:
                nr_p = int(request.form.get('p'))
                nr_g = int(request.form.get('g'))
                nr_x = int(request.form.get('x'))

                if not is_prime(nr_p):
                    nr_key_error = "p는 소수여야 합니다."
                elif not (1 < nr_g < nr_p):
                    nr_key_error = "g는 1 < g < p를 만족해야 합니다."
                elif not (1 < nr_x < nr_p - 1):
                    nr_key_error = "x는 1 < x < p-1을 만족해야 합니다."
                else:
                    nr_y = pow(nr_g, nr_x, nr_p)
                    # Store generated keys in session
                    session['nr_p'] = nr_p
                    session['nr_g'] = nr_g
                    session['nr_x'] = nr_x
                    session['nr_y'] = nr_y

            except ValueError:
                nr_key_error = "유효한 숫자를 입력해주세요."

        elif nr_operation == 'sign':
            try:
                nr_message_sign = request.form.get('message')
                nr_p_sign = int(request.form.get('p'))
                nr_g_sign = int(request.form.get('g'))
                nr_x_sign = int(request.form.get('x'))
                nr_k_sign = int(request.form.get('k'))

                if not is_prime(nr_p_sign):
                    nr_sign_error = "p는 소수여야 합니다."
                elif not (1 < nr_k_sign < nr_p_sign - 1) or gcd(nr_k_sign, nr_p_sign - 1) != 1:
                    nr_sign_error = "k는 1 < k < p-1 이고 gcd(k, p-1) = 1을 만족하는 무작위 정수여야 합니다."
                else:
                    h = int(hashlib.sha256(nr_message_sign.encode()).hexdigest(), 16) % nr_p_sign # Use SHA-256
                    
                    # Nyberg-Rueppel specific signing steps
                    r = pow(nr_g_sign, nr_k_sign, nr_p_sign)
                    s = (nr_x_sign * r + nr_k_sign * h) % (nr_p_sign - 1) # Simplified for demonstration

                    nr_r_result = r
                    nr_s_result = s

            except ValueError:
                nr_sign_error = "유효한 숫자를 입력해주세요."

        elif nr_operation == 'verify':
            try:
                nr_message_verify = request.form.get('message')
                nr_r_verify = int(request.form.get('r'))
                nr_s_verify = int(request.form.get('s'))
                nr_p_verify = int(request.form.get('p'))
                nr_g_verify = int(request.form.get('g'))
                nr_y_verify = int(request.form.get('y'))

                h_prime = int(hashlib.sha256(nr_message_verify.encode()).hexdigest(), 16) % nr_p_verify # Use SHA-256

                # Nyberg-Rueppel specific verification steps
                # Note: This is a simplified verification. A full NR verification is more complex.
                # For demonstration, we'll check if g^s == y^r * r^h (mod p)
                # This is a common variant, but actual NR might differ slightly.
                left_side = pow(nr_g_verify, nr_s_verify, nr_p_verify)
                right_side = (pow(nr_y_verify, nr_r_verify, nr_p_verify) * pow(nr_r_verify, h_prime, nr_p_verify)) % nr_p_verify

                if left_side == right_side:
                    nr_verification_result = "서명 유효함"
                else:
                    nr_verification_result = "서명 유효하지 않음"

            except ValueError:
                nr_verify_error = "유효한 숫자를 입력해주세요."

    return render_template('nyberg_rueppel.html',
                           nr_p=nr_p, nr_g=nr_g, nr_x=nr_x, nr_y=nr_y, nr_key_error=nr_key_error,
                           nr_message_sign=nr_message_sign, nr_p_sign=nr_p_sign, nr_g_sign=nr_g_sign, nr_x_sign=nr_x_sign, nr_k_sign=nr_k_sign, nr_r_result=nr_r_result, nr_s_result=nr_s_result, nr_sign_error=nr_sign_error,
                           nr_message_verify=nr_message_verify, nr_r_verify=nr_r_verify, nr_s_verify=nr_s_verify, nr_p_verify=nr_p_verify, nr_g_verify=nr_g_verify, nr_y_verify=nr_y_verify, nr_verification_result=nr_verification_result, nr_verify_error=nr_verify_error,
                           session_nr_p=session.get('nr_p'), session_nr_g=session.get('nr_g'), session_nr_x=session.get('nr_x'), session_nr_y=session.get('nr_y'))

@app.route('/kcdsa', methods=['GET', 'POST'])
def kcdsa():
    kcdsa_p, kcdsa_q, kcdsa_g, kcdsa_x, kcdsa_y, kcdsa_key_error = None, None, None, None, None, None
    kcdsa_message_sign, kcdsa_p_sign, kcdsa_q_sign, kcdsa_g_sign, kcdsa_x_sign, kcdsa_k_sign, kcdsa_r_result, kcdsa_s_result, kcdsa_sign_error = None, None, None, None, None, None, None, None, None
    kcdsa_message_verify, kcdsa_p_verify, kcdsa_q_verify, kcdsa_g_verify, kcdsa_y_verify, kcdsa_r_verify, kcdsa_s_verify, kcdsa_verification_result, kcdsa_verify_error = None, None, None, None, None, None, None, None, None

    # Retrieve stored keys from session if available
    if 'kcdsa_p' in session:
        kcdsa_p = session['kcdsa_p']
    if 'kcdsa_q' in session:
        kcdsa_q = session['kcdsa_q']
    if 'kcdsa_g' in session:
        kcdsa_g = session['kcdsa_g']
    if 'kcdsa_x' in session:
        kcdsa_x = session['kcdsa_x']
    if 'kcdsa_y' in session:
        kcdsa_y = session['kcdsa_y']

    if request.method == 'POST':
        kcdsa_operation = request.form.get('kcdsa_operation')

        if kcdsa_operation == 'generate_keys':
            try:
                # KCDSA uses specific parameter generation. For demonstration, we'll adapt DSA-like generation.
                # In a real KCDSA implementation, p, q, g would be generated according to the standard.
                L = int(request.form.get('L', 512)) # Bit length for p
                N = int(request.form.get('N', 160)) # Bit length for q

                kcdsa_p, kcdsa_q, kcdsa_g = generate_dsa_params(L, N) # Reusing DSA param generation for simplicity

                if kcdsa_p is None or kcdsa_q is None or kcdsa_g is None:
                    kcdsa_key_error = "KCDSA 파라미터 (p, q, g) 생성에 실패했습니다. 더 큰 범위나 다른 값을 시도해보세요."
                else:
                    # Generate private key x (0 < x < q)
                    kcdsa_x = random.randint(1, kcdsa_q - 1)
                    # Calculate public key y (y = g^x mod p)
                    kcdsa_y = pow(kcdsa_g, kcdsa_x, kcdsa_p)

                    session['kcdsa_p'] = kcdsa_p
                    session['kcdsa_q'] = kcdsa_q
                    session['kcdsa_g'] = kcdsa_g
                    session['kcdsa_x'] = kcdsa_x
                    session['kcdsa_y'] = kcdsa_y

            except ValueError:
                kcdsa_key_error = "유효한 숫자를 입력해주세요."

        elif kcdsa_operation == 'sign':
            try:
                kcdsa_message_sign = request.form.get('message')
                kcdsa_p_sign = int(request.form.get('p'))
                kcdsa_q_sign = int(request.form.get('q'))
                kcdsa_g_sign = int(request.form.get('g'))
                kcdsa_x_sign = int(request.form.get('x'))
                kcdsa_k_sign = int(request.form.get('k'))

                if not (0 < kcdsa_k_sign < kcdsa_q_sign) or gcd(kcdsa_k_sign, kcdsa_q_sign) != 1:
                    kcdsa_sign_error = "k는 0 < k < q 이고 gcd(k, q) = 1을 만족하는 무작위 정수여야 합니다."
                else:
                    # KCDSA uses a specific hash function (e.g., HAS-160). For demonstration, we use SHA-256.
                    h = int(hashlib.sha256(kcdsa_message_sign.encode()).hexdigest(), 16)
                    e = h % kcdsa_q # Hash value modulo q
                    if e == 0: e = 1 # KCDSA specific: if e is 0, set to 1

                    # KCDSA specific signing steps (simplified for demonstration)
                    # This is a simplified adaptation of DSA-like signing for KCDSA concept.
                    r = pow(kcdsa_g_sign, kcdsa_k_sign, kcdsa_p_sign) % kcdsa_q
                    if r == 0:
                        kcdsa_sign_error = "r이 0이 되어 서명에 실패했습니다. 다른 k 값을 시도해보세요."
                    else:
                        k_inv = mod_inverse(kcdsa_k_sign, kcdsa_q_sign)
                        if k_inv is None:
                            kcdsa_sign_error = "k의 모듈러 역원을 찾을 수 없습니다."
                        else:
                            s = (k_inv * (e + kcdsa_x_sign * r)) % kcdsa_q
                            if s == 0:
                                kcdsa_sign_error = "s가 0이 되어 서명에 실패했습니다. 다른 k 값을 시도해보세요."
                            else:
                                kcdsa_r_result = r
                                kcdsa_s_result = s

            except ValueError:
                kcdsa_sign_error = "유효한 숫자를 입력해주세요."

        elif kcdsa_operation == 'verify':
            try:
                kcdsa_message_verify = request.form.get('message')
                kcdsa_p_verify = int(request.form.get('p'))
                kcdsa_q_verify = int(request.form.get('q'))
                kcdsa_g_verify = int(request.form.get('g'))
                kcdsa_y_verify = int(request.form.get('y'))
                kcdsa_r_verify = int(request.form.get('r'))
                kcdsa_s_verify = int(request.form.get('s'))

                if not (0 < kcdsa_r_verify < kcdsa_q_verify) or not (0 < kcdsa_s_verify < kcdsa_q_verify):
                    kcdsa_verify_error = "서명 (r, s) 값이 유효하지 않습니다. (0 < r, s < q)"
                else:
                    h_prime = int(hashlib.sha256(kcdsa_message_verify.encode()).hexdigest(), 16)
                    e_prime = h_prime % kcdsa_q # Hash value modulo q
                    if e_prime == 0: e_prime = 1 # KCDSA specific: if e_prime is 0, set to 1

                    w = mod_inverse(kcdsa_s_verify, kcdsa_q_verify)
                    if w is None:
                        kcdsa_verify_error = "s의 모듈러 역원을 찾을 수 없습니다."
                    else:
                        u1 = (e_prime * w) % kcdsa_q_verify
                        u2 = (kcdsa_r_verify * w) % kcdsa_q_verify
                        v = (pow(kcdsa_g_verify, u1, kcdsa_p_verify) * pow(kcdsa_y_verify, u2, kcdsa_p_verify)) % kcdsa_p_verify % kcdsa_q_verify

                        if v == kcdsa_r_verify:
                            kcdsa_verification_result = "서명 유효함"
                        else:
                            kcdsa_verification_result = "서명 유효하지 않음"

            except ValueError:
                kcdsa_verify_error = "유효한 숫자를 입력해주세요."

    return render_template('kcdsa.html',
                           kcdsa_p=kcdsa_p, kcdsa_q=kcdsa_q, kcdsa_g=kcdsa_g, kcdsa_x=kcdsa_x, kcdsa_y=kcdsa_y, kcdsa_key_error=kcdsa_key_error,
                           kcdsa_message_sign=kcdsa_message_sign, kcdsa_p_sign=kcdsa_p_sign, kcdsa_q_sign=kcdsa_q_sign, kcdsa_g_sign=kcdsa_g_sign, kcdsa_x_sign=kcdsa_x_sign, kcdsa_k_sign=kcdsa_k_sign, kcdsa_r_result=kcdsa_r_result, kcdsa_s_result=kcdsa_s_result, kcdsa_sign_error=kcdsa_sign_error,
                           kcdsa_message_verify=kcdsa_message_verify, kcdsa_p_verify=kcdsa_p_verify, kcdsa_q_verify=kcdsa_q_verify, kcdsa_g_verify=kcdsa_g_verify, kcdsa_y_verify=kcdsa_y_verify, kcdsa_r_verify=kcdsa_r_verify, kcdsa_s_verify=kcdsa_s_verify, kcdsa_verification_result=kcdsa_verification_result, kcdsa_verify_error=kcdsa_verify_error,
                           session_kcdsa_p=session.get('kcdsa_p'), session_kcdsa_q=session.get('kcdsa_q'), session_kcdsa_g=session.get('kcdsa_g'), session_kcdsa_x=session.get('kcdsa_x'), session_kcdsa_y=session.get('kcdsa_y'))

@app.route('/comparison')
def comparison():
    return render_template('comparison.html')

@app.route('/prime_generator', methods=['GET', 'POST'])
def prime_generator():
    generated_prime = None
    generated_primitive_root = None
    prime_generator_error = None

    if request.method == 'POST':
        try:
            min_val = int(request.form.get('min_val', 100))
            max_val = int(request.form.get('max_val', 1000))

            if min_val >= max_val:
                prime_generator_error = "최소값은 최대값보다 작아야 합니다."
            else:
                generated_prime = generate_random_prime(min_val, max_val)
                if generated_prime:
                    generated_primitive_root = find_primitive_root(generated_prime)
                else:
                    prime_generator_error = "지정된 범위 내에서 소수를 찾을 수 없습니다."

        except ValueError:
            prime_generator_error = "유효한 숫자를 입력해주세요."

    return render_template('prime_generator.html',
                           generated_prime=generated_prime,
                           generated_primitive_root=generated_primitive_root,
                           prime_generator_error=prime_generator_error)

@app.route('/modulo_calculator', methods=['GET', 'POST'])
def modulo_calculator():
    add_a, add_b, add_n, add_result = None, None, None, None
    mul_a, mul_b, mul_n, mul_result = None, None, None, None
    exp_base, exp_exponent, exp_n, exp_result = None, None, None, None
    inv_a, inv_n, inv_result, inv_error = None, None, None, None

    if request.method == 'POST':
        operation = request.form.get('operation')

        if operation == 'add':
            add_a = int(request.form.get('a'))
            add_b = int(request.form.get('b'))
            add_n = int(request.form.get('n'))
            add_result = (add_a + add_b) % add_n
        elif operation == 'multiply':
            mul_a = int(request.form.get('a'))
            mul_b = int(request.form.get('b'))
            mul_n = int(request.form.get('n'))
            mul_result = (mul_a * mul_b) % mul_n
        elif operation == 'exponentiate':
            exp_base = int(request.form.get('base'))
            exp_exponent = int(request.form.get('exponent'))
            exp_n = int(request.form.get('n'))
            exp_result = pow(exp_base, exp_exponent, exp_n)
        elif operation == 'inverse':
            inv_a = int(request.form.get('a'))
            inv_n = int(request.form.get('n'))
            inverse = mod_inverse(inv_a, inv_n)
            if inverse is not None:
                inv_result = inverse
            else:
                inv_error = f"{inv_a}의 {inv_n}에 대한 모듈로 역원이 존재하지 않습니다. (gcd({inv_a}, {inv_n}) != 1)"

    return render_template('modulo_calculator.html',
                           add_a=add_a, add_b=add_b, add_n=add_n, add_result=add_result,
                           mul_a=mul_a, mul_b=mul_b, mul_n=mul_n, mul_result=mul_result,
                           exp_base=exp_base, exp_exponent=exp_exponent, exp_n=exp_n, exp_result=exp_result,
                           inv_a=inv_a, inv_n=inv_n, inv_result=inv_result, inv_error=inv_error)

@app.route('/standards')
def standards():
    return render_template('standards.html')

@app.route('/other_content')
def other_content():
    return render_template('other_content.html')

if __name__ == '__main__':
    app.run(debug=True)