# Project Overview

This project aims to create a web application for demonstrating and experimenting with the ElGamal encryption algorithm. The user interface and all content will be in Korean.

**Core Technologies:**
*   **Backend:** Python
*   **Frontend Framework:** To be determined. Initial options include Streamlit, Flask, or Django. Given the goal of creating an educational and interactive tool, **Flask** is a good starting point as it is lightweight and flexible.

**Architecture:**
The application will be a multi-page web app featuring a left-side menu to allow users to easily switch between different sections.

**Pages:**
1.  **Introduction to ElGamal:** History and a brief overview of the algorithm.
2.  **System Explanation:** Detailed description of the encryption and decryption processes.
3.  **Key Generation:** A screen to generate public and private keys.
4.  **Encrypt/Decrypt:** A screen to experiment with the encryption and decryption process.
5.  **Modular Calculator:** A screen to perform modular calculations like `x*y mod p`, `y^k mod p`, and `x^(-1) mod p`.
6.  **Cryptanalysis:** Explanation of known methods for breaking the ElGamal cipher.
7.  **Special Topics:** A section for interesting facts, research, and other related information about ElGamal.

# Building and Running

As the project is just starting, the specific commands are not yet defined. Here is a recommended setup using **Flask**:

**1. Setup Python Environment:**
```bash
# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate
```

**2. Install Dependencies:**
A `requirements.txt` file should be created. To start, it will contain Flask.
```
# requirements.txt
flask
```
Install the dependencies:
```bash
pip install -r requirements.txt
```

**3. Run the Application:**
An `app.py` file will be the main entry point.
```bash
# Set the Flask app environment variable
export FLASK_APP=app.py

# Run the development server
flask run
```

# Development Conventions

*   **Language:** All user-facing text in the web application must be in Korean.
*   **UI:** The application must use a left-side menu for navigation between pages.
*   **Code:** The backend logic, including the ElGamal algorithm implementation, will be written in Python.
