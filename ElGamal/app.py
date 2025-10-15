from flask import Flask, render_template, request, session
import elgamal

app = Flask(__name__)
app.secret_key = 'a_random_secret_key_for_session' # In production, use a real, secure secret key

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/system")
def system():
    return render_template("system.html")

@app.route("/cryptanalysis")
def cryptanalysis():
    return render_template("cryptanalysis.html")

@app.route("/special")
def special():
    return render_template("special.html")

@app.route("/keys", methods=['GET', 'POST'])
def keys():
    if request.method == 'POST':
        bits = int(request.form.get('bits', 256))
        keys = elgamal.generate_keys(bits)
        session['keys'] = keys # Store keys in the session
        session.pop('form_input', None) # Clear old experiment form input
        session.pop('calc_form_input', None) # Clear old calculator form input
        return render_template("keys.html", keys=keys)
    return render_template("keys.html")

@app.route("/experiment", methods=['GET', 'POST'])
def experiment():
    result = None
    form_input = session.get('form_input', {})

    if request.method == 'POST':
        form_input.update(request.form.to_dict())
        session['form_input'] = form_input

        if 'encrypt' in request.form:
            p = int(form_input['p'])
            g = int(form_input['g'])
            y = int(form_input['y'])
            msg = int(form_input['message'])
            k_str = form_input.get('k', '')
            k = int(k_str) if k_str.isdigit() else 0
            c1, c2 = elgamal.encrypt(msg, p, g, y, k)
            result = f"암호문 (c1, c2): ({c1}, {c2})"
        elif 'decrypt' in request.form:
            p = int(form_input['p'])
            x = int(form_input['x'])
            c1 = int(form_input['c1'])
            c2 = int(form_input['c2'])
            decrypted_msg = elgamal.decrypt(c1, c2, x, p)
            result = f"복호화된 메시지: {decrypted_msg}"
            
    keys_from_session = session.get('keys', None)
    return render_template("experiment.html", result=result, keys=keys_from_session, form_input=form_input)

@app.route("/calculator", methods=['GET', 'POST'])
def calculator():
    calc_result = None
    form_input = session.get('calc_form_input', {})

    # If mod_p is not in our form state, try to get it from the generated keys
    if not form_input.get('mod_p') and 'keys' in session:
        form_input['mod_p'] = session['keys']['public_key']['p']

    if request.method == 'POST':
        form_input.update(request.form.to_dict())
        session['calc_form_input'] = form_input

        mod_p = int(form_input['mod_p'])
        num1 = int(form_input['num1'])
        operation = form_input['operation']
        
        if operation == 'power':
            num2 = int(form_input['num2'])
            calc_result = elgamal.power(num1, num2, mod_p)
        elif operation == 'inverse':
            calc_result = elgamal.mod_inverse(num1, mod_p)
        elif operation == 'multiply':
            num2 = int(form_input['num2'])
            calc_result = (num1 * num2) % mod_p

    return render_template("calculator.html", calc_result=calc_result, form_input=form_input)

if __name__ == "__main__":
    app.run(debug=True)
