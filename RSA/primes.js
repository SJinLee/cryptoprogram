document.getElementById('generate-prime').addEventListener('click', function() {
  const bits = parseInt(document.getElementById('bits').value, 10);
  const generatedPrimeTextArea = document.getElementById('generated-prime');

  if (bits < 2) {
    alert('Number of bits must be at least 2.');
    return;
  }

  generatedPrimeTextArea.value = 'Generating...';

  // Use a timeout to avoid blocking the UI thread, allowing the 'Generating...' message to display.
  setTimeout(() => {
    // The smallest number with `bits` bits is 2^(bits-1)
    const min = bigInt.one.shiftLeft(bits - 1);
    // The largest number with `bits` bits is 2^bits - 1
    const max = bigInt.one.shiftLeft(bits).subtract(1);

    let primeCandidate = bigInt.randBetween(min, max);

    // Ensure it's an odd number
    if (primeCandidate.isEven()) {
      primeCandidate = primeCandidate.add(1);
    }

    // Search for a prime
    while (!primeCandidate.isPrime()) {
      primeCandidate = primeCandidate.add(2);
      // If we go beyond the max, restart the search to stay within the desired bit length.
      if (primeCandidate.greater(max)) {
          primeCandidate = bigInt.randBetween(min, max);
          if (primeCandidate.isEven()) {
              primeCandidate = primeCandidate.add(1);
          }
      }
    }

    generatedPrimeTextArea.value = primeCandidate.toString();
  }, 10);
});
