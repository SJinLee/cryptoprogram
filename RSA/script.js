document.getElementById('generate').addEventListener('click', function() {
  const p = bigInt(document.getElementById('p').value);
  const q = bigInt(document.getElementById('q').value);

  // Use the library's isPrime method. Note: This can be slow for very large numbers.
  if (!p.isPrime() || !q.isPrime()) {
    alert('Please enter prime numbers for p and q.');
    return;
  }

  const n = p.multiply(q);
  const phi = p.subtract(1).multiply(q.subtract(1));

  let e = bigInt(65537); // Common choice for e
  if (bigInt.gcd(e, phi).notEquals(1)) {
      e = bigInt(3);
      while(bigInt.gcd(e, phi).notEquals(1)) {
          e = e.add(2);
      }
  }

  const d = e.modInv(phi);

  document.getElementById('public-key').textContent = `(${e.toString()}, ${n.toString()})`;
  document.getElementById('private-key').textContent = `(${d.toString()}, ${n.toString()})`;
});

document.getElementById('encrypt').addEventListener('click', function() {
  const message = document.getElementById('message').value;
  const publicKeyText = document.getElementById('public-key').textContent;
  
  if (!publicKeyText) {
    alert('Please generate keys first.');
    return;
  }

  const [eStr, nStr] = publicKeyText.replace('(', '').replace(')', '').split(', ');
  const e = bigInt(eStr);
  const n = bigInt(nStr);

  const encryptedMessage = [];
  for (let i = 0; i < message.length; i++) {
    const charCode = message.charCodeAt(i);
    const encryptedChar = bigInt(charCode).modPow(e, n);
    encryptedMessage.push(encryptedChar.toString());
  }

  document.getElementById('encrypted-message').textContent = encryptedMessage.join(' ');
});

document.getElementById('decrypt').addEventListener('click', function() {
  const encryptedMessage = document.getElementById('encrypted').value;
  const privateKeyText = document.getElementById('private-key').textContent;

  if (!privateKeyText) {
    alert('Please generate keys first.');
    return;
  }
  
  if (!encryptedMessage) {
    alert('Please enter a message to decrypt.');
    return;
  }

  const [dStr, nStr] = privateKeyText.replace('(', '').replace(')', '').split(', ');
  const d = bigInt(dStr);
  const n = bigInt(nStr);
  const encryptedChars = encryptedMessage.split(' ');

  let decryptedMessage = '';
  for (let i = 0; i < encryptedChars.length; i++) {
    if(encryptedChars[i]) {
        const decryptedChar = bigInt(encryptedChars[i]).modPow(d, n);
        decryptedMessage += String.fromCharCode(decryptedChar.toJSNumber());
    }
  }

  document.getElementById('decrypted-message').textContent = decryptedMessage;
});
