from flask import Flask, render_template, request, session, redirect, url_for
from des_logic import generate_round_keys, encrypt, decrypt, permute, s_box_substitution, xor, IP, E, P, PC1, PC2, SHIFTS
import time
import random
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- Helper for brute force simulation ---
def generate_key_space(correct_key, size=1000):
    keyspace = {correct_key}
    while len(keyspace) < size:
        random_key = "".join(random.choice('01') for _ in range(64))
        keyspace.add(random_key)
    
    key_list = list(keyspace)
    random.shuffle(key_list)
    return key_list


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/introduction')
def introduction():
    return render_template('introduction.html')

@app.route('/key-generation', methods=['GET', 'POST'])
def key_generation():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'clear_session':
            for key in list(session.keys()):
                if key.startswith('kg_'):
                    session.pop(key)
            return redirect(url_for('key_generation'))

        if action == 'generate_all':
            key_str = request.form['key']
            session['kg_key_str'] = key_str
            if len(key_str) == 64 and all(c in '01' for c in key_str):
                round_keys_list = generate_round_keys(key_str)
                session['kg_round_keys'] = ["".join(map(str, rk)) for rk in round_keys_list]
        
        elif action == 'calc_pc1':
            pc1_key = request.form.get('pc1_key')
            session['kg_pc1_key'] = pc1_key
            if pc1_key and len(pc1_key) == 64 and all(c in '01' for c in pc1_key):
                key_bits = [int(b) for b in pc1_key]
                pc1_result_bits = permute(key_bits, PC1)
                session['kg_pc1_result'] = "".join(map(str, pc1_result_bits))

        elif action == 'calc_shift_c' or action == 'calc_shift_d':
            block_type = 'c' if action == 'calc_shift_c' else 'd'
            shift_block = request.form.get(f'shift_block_{block_type}')
            round_num_str = request.form.get(f'round_num_{block_type}')
            session[f'kg_shift_block_{block_type}'] = shift_block
            session[f'kg_round_num_{block_type}'] = round_num_str
            if shift_block and round_num_str and len(shift_block) == 28 and all(c in '01' for c in shift_block):
                try:
                    round_num = int(round_num_str)
                    if 1 <= round_num <= 16:
                        shift_amount = SHIFTS[round_num - 1]
                        block_bits = [int(b) for b in shift_block]
                        shifted_bits = block_bits[shift_amount:] + block_bits[:shift_amount]
                        session[f'kg_shift_result_{block_type}'] = "".join(map(str, shifted_bits))
                        session[f'kg_shift_amount_{block_type}'] = shift_amount
                except ValueError:
                    pass

        elif action == 'calc_pc2':
            pc2_block = request.form.get('pc2_block')
            session['kg_pc2_block'] = pc2_block
            if pc2_block and len(pc2_block) == 56 and all(c in '01' for c in pc2_block):
                block_bits = [int(b) for b in pc2_block]
                pc2_result_bits = permute(block_bits, PC2)
                session['kg_pc2_result'] = "".join(map(str, pc2_result_bits))
        
        return redirect(url_for('key_generation'))

    return render_template('key_generation.html')

@app.route('/encryption', methods=['GET', 'POST'])
def encryption():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'clear_session':
            for key in list(session.keys()):
                if key.startswith('enc_'):
                    session.pop(key)
            return redirect(url_for('encryption'))

        if action == 'encrypt_all':
            key_str = request.form['key']
            plaintext_str = request.form['plaintext']
            session['enc_key_str'] = key_str
            session['enc_plaintext_str'] = plaintext_str
            if (len(key_str) == 64 and all(c in '01' for c in key_str)) and (len(plaintext_str) == 64 and all(c in '01' for c in plaintext_str)):
                round_keys = generate_round_keys(key_str)
                ciphertext, round_logs = encrypt(plaintext_str, round_keys)
                session['enc_ciphertext'] = ciphertext
                session['enc_round_logs'] = round_logs
        
        elif action == 'calc_ip':
            ip_block = request.form.get('ip_block')
            session['enc_ip_block'] = ip_block
            if ip_block and len(ip_block) == 64 and all(c in '01' for c in ip_block):
                bits = [int(b) for b in ip_block]
                session['enc_ip_result'] = "".join(map(str, permute(bits, IP)))

        elif action == 'calc_e':
            e_block = request.form.get('e_block')
            session['enc_e_block'] = e_block
            if e_block and len(e_block) == 32 and all(c in '01' for c in e_block):
                bits = [int(b) for b in e_block]
                session['enc_e_result'] = "".join(map(str, permute(bits, E)))

        elif action == 'calc_xor_key':
            e_block = request.form.get('exork_e_block')
            k_block = request.form.get('exork_k_block')
            session['enc_exork_e_block'] = e_block
            session['enc_exork_k_block'] = k_block
            if e_block and k_block and len(e_block) == 48 and len(k_block) == 48 and all(c in '01' for c in e_block+k_block):
                e_bits = [int(b) for b in e_block]
                k_bits = [int(b) for b in k_block]
                session['enc_exork_result'] = "".join(map(str, xor(e_bits, k_bits)))

        elif action == 'calc_sbox':
            sbox_block = request.form.get('sbox_block')
            session['enc_sbox_block'] = sbox_block
            if sbox_block and len(sbox_block) == 48 and all(c in '01' for c in sbox_block):
                bits = [int(b) for b in sbox_block]
                session['enc_sbox_result'] = "".join(map(str, s_box_substitution(bits)))

        elif action == 'calc_p':
            p_block = request.form.get('p_block')
            session['enc_p_block'] = p_block
            if p_block and len(p_block) == 32 and all(c in '01' for c in p_block):
                bits = [int(b) for b in p_block]
                session['enc_p_result'] = "".join(map(str, permute(bits, P)))

        return redirect(url_for('encryption'))

    return render_template('encryption.html')

@app.route('/avalanche', methods=['GET', 'POST'])
def avalanche():
    if request.method == 'POST':
        key_str = request.form['key']
        p1_str = request.form['plaintext1']
        p2_str = request.form['plaintext2']

        if not (len(key_str) == 64 and len(p1_str) == 64 and len(p2_str) == 64 and all(c in '01' for c in key_str+p1_str+p2_str)):
            return render_template('avalanche.html', error="잘못된 입력입니다. 모든 필드가 64비트 이진 문자열인지 확인하세요.", p1_str=p1_str, p2_str=p2_str, key_str=key_str)

        round_keys = generate_round_keys(key_str)
        c1, _ = encrypt(p1_str, round_keys)
        c2, _ = encrypt(p2_str, round_keys)

        bit_difference = sum(b1 != b2 for b1, b2 in zip(c1, c2))

        results = {
            'c1': c1,
            'c2': c2,
            'bit_difference': bit_difference,
            'comparison': zip(c1, c2)
        }

        return render_template('avalanche.html', results=results, p1_str=p1_str, p2_str=p2_str, key_str=key_str)

    return render_template('avalanche.html')

@app.route('/brute-force', methods=['GET', 'POST'])
def brute_force():
    if request.method == 'POST':
        key_str = request.form['key']
        plaintext_str = request.form['plaintext']

        if not (len(key_str) == 64 and all(c in '01' for c in key_str)) or not (len(plaintext_str) == 64 and all(c in '01' for c in plaintext_str)):
            return render_template('brute_force.html', error="잘못된 입력입니다. 모든 필드가 64비트 이진 문자열인지 확인하세요.", plaintext_str=plaintext_str, key_str=key_str)

        # 1. Create the target ciphertext
        target_ciphertext, _ = encrypt(plaintext_str, generate_round_keys(key_str))

        # 2. Create a small keyspace for the simulation
        keyspace = generate_key_space(key_str, size=2000)

        # 3. Run the simulation
        start_time = time.time()
        found_key = None
        attempts = 0
        for test_key in keyspace:
            attempts += 1
            test_round_keys = generate_round_keys(test_key)
            decrypted_text = decrypt(target_ciphertext, test_round_keys)
            if decrypted_text == plaintext_str:
                found_key = test_key
                break
        end_time = time.time()

        results = {
            'ciphertext': target_ciphertext,
            'found_key': found_key,
            'attempts': attempts,
            'time_taken': end_time - start_time
        }

        return render_template('brute_force.html', results=results, plaintext_str=plaintext_str, key_str=key_str)

    return render_template('brute_force.html')

if __name__ == '__main__':
    app.run(debug=True)
