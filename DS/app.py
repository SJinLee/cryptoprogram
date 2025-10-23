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
