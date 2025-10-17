from flask import Flask, render_template, request, session, redirect, url_for
from knapsack_logic import (power, mod_inverse, generate_keys, encrypt, decrypt, 
                              create_random_private_key)

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # 세션 관리를 위한 시크릿 키

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/explain')
def explain():
    return render_template('explain.html')

@app.route('/keys', methods=['GET', 'POST'])
def keys():
    if request.method == 'POST':
        try:
            w, p, y = create_random_private_key()
            private_key, public_key = generate_keys(w, p, y)

            session['generated_w'] = str(w)
            session['generated_p'] = str(p)
            session['generated_y'] = str(y)
            session['private_key'] = str(private_key)
            session['public_key'] = str(public_key)

            key_len = len(public_key)
            session['max_plaintext_val'] = str((2**key_len) - 1)
            session.pop('plaintext', None)
            session.pop('binary_plaintext', None)
            session.pop('ciphertext', None)
            session.pop('decrypted_text', None)

            # 계산기 p 값 자동 채우기
            session['add_p'] = p
            session['mul_p'] = p
            session['pow_p'] = p
            session['inv_p'] = p

        except Exception as e:
            session['private_key'] = f"오류: {e}"
            session['public_key'] = ""

        return redirect(url_for('keys'))

    return render_template('keys.html')

@app.route('/crypto', methods=['GET', 'POST'])
def crypto():
    if request.method == 'POST':
        action = request.form.get('action')
        try:
            if action == 'encrypt':
                plaintext = request.form['plaintext']
                public_key_str = session.get('public_key')
                if not public_key_str:
                    raise ValueError("공개키가 생성되지 않았습니다.")
                
                public_key = eval(public_key_str)
                ciphertext, binary_plain = encrypt(public_key, int(plaintext))
                
                session['plaintext'] = plaintext
                session['binary_plaintext'] = binary_plain
                session['ciphertext'] = str(ciphertext)
                session['ciphertext_input'] = str(ciphertext)

            elif action == 'decrypt':
                ciphertext_input = request.form['ciphertext_input']
                private_key_str = session.get('private_key')
                if not private_key_str:
                    raise ValueError("개인키가 생성되지 않았습니다.")
                
                private_key = eval(private_key_str)
                decrypted_text = decrypt(private_key, int(ciphertext_input))

                session['ciphertext_input'] = ciphertext_input
                session['decrypted_text'] = str(decrypted_text)

        except Exception as e:
            if action == 'encrypt':
                session['ciphertext'] = f"오류: {e}"
            elif action == 'decrypt':
                session['decrypted_text'] = f"오류: {e}"
        
        return redirect(url_for('crypto'))

    return render_template('crypto.html')

@app.route('/calculator', methods=['GET', 'POST'])
def calculator():
    if request.method == 'POST':
        action = request.form.get('action')
        try:
            if action == 'add':
                add_x = int(request.form['add_x'])
                add_y = int(request.form['add_y'])
                add_p = int(request.form['add_p'])
                session['add_x'] = add_x
                session['add_y'] = add_y
                session['add_p'] = add_p
                session['add_result'] = (add_x + add_y) % add_p
            elif action == 'multiply':
                mul_x = int(request.form['mul_x'])
                mul_y = int(request.form['mul_y'])
                mul_p = int(request.form['mul_p'])
                session['mul_x'] = mul_x
                session['mul_y'] = mul_y
                session['mul_p'] = mul_p
                session['mul_result'] = (mul_x * mul_y) % mul_p
            elif action == 'power':
                pow_y = int(request.form['pow_y'])
                pow_k = int(request.form['pow_k'])
                pow_p = int(request.form['pow_p'])
                session['pow_y'] = pow_y
                session['pow_k'] = pow_k
                session['pow_p'] = pow_p
                session['pow_result'] = power(pow_y, pow_k, pow_p)
            elif action == 'inverse':
                inv_x = int(request.form['inv_x'])
                inv_p = int(request.form['inv_p'])
                session['inv_x'] = inv_x
                session['inv_p'] = inv_p
                session['inv_result'] = mod_inverse(inv_x, inv_p)
        except Exception as e:
            if action == 'add': session['add_result'] = f"오류: {e}"
            elif action == 'multiply': session['mul_result'] = f"오류: {e}"
            elif action == 'power': session['pow_result'] = f"오류: {e}"
            elif action == 'inverse': session['inv_result'] = f"오류: {e}"
        return redirect(url_for('calculator'))

    return render_template('calculator.html')

@app.route('/cryptanalysis')
def cryptanalysis():
    return render_template('cryptanalysis.html')

@app.route('/misc')
def misc():
    return render_template('misc.html')

if __name__ == '__main__':
    app.run(debug=True)
