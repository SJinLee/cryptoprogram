# Project: RSA Encryption Tool

## Project Overview

This project is a web-based tool for demonstrating the RSA encryption algorithm. It features a tabbed interface that separates the main RSA functionality (key generation, encryption, decryption) from a utility for generating large prime numbers.

The project is built with standard web technologies:

*   **HTML (`index.html`)**: Defines the structure for the entire user interface, including the tabbed layout for both the RSA tool and the prime generator.
*   **CSS (`style.css`)**: Provides styling for the layout and the tabbed interface.
*   **JavaScript (`script.js`)**: Implements the key generation, encryption, and decryption logic for the main RSA tool.
*   **JavaScript (`primes.js`)**: Implements the prime number generation logic for the prime generator tab.
*   **BigInteger.js**: An external library used for handling the large integer arithmetic required for RSA.

## Building and Running

This is a static web project with no build process.

To run the application, simply open the `index.html` file in any modern web browser.

## Development Conventions

*   The UI is organized into a tabbed interface, with JavaScript logic in `index.html` handling the switching between the 'RSA Encryption' and 'Prime Generator' tabs.
*   The core RSA logic is contained in `script.js`.
*   The prime generation logic is in `primes.js`.
*   All RSA-related arithmetic (key generation, encryption, decryption) is handled by the `BigInteger.js` library to ensure performance and support for large numbers.
*   The previously inefficient private key calculation has been optimized using the library's `modInv` function, allowing for near-instant key generation.
*   Encryption and decryption are performed on a character-by-character basis, converting each character to its character code for mathematical operations.
*   Redundant helper functions have been removed from the script in favor of the library's built-in methods.
