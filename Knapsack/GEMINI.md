# Project Overview

This project is a web application for experimenting with the Merkle-Hellman Knapsack cryptosystem. The application will be built using Python and the Flask web framework. The user interface and all content will be in Korean.

## Key Features

*   **Educational Content:** Provides introductions and explanations of the Merkle-Hellman Knapsack cipher, including its history, different types (I and II), and known cryptanalysis methods.
*   **Interactive Tools:**
    *   A tool to generate public and private keys.
    *   A tool to perform encryption and decryption experiments.
    *   A modular arithmetic calculator for expressions like `x*y mod p`, `y^k mod p`, and `x^(-1) mod p`.
*   **User Experience:**
    *   A persistent side navigation menu for easy access to all pages.
    *   Input values on forms will be preserved across submissions and page navigations.

# Building and Running

**1. Install Dependencies:**

It is assumed that the project dependencies are listed in a `requirements.txt` file. Install them using pip:

```bash
pip install -r requirements.txt
```

*TODO: Create the `requirements.txt` file and add `Flask`.*

**2. Run the Application:**

The main application file is expected to be `app.py`. To run the Flask development server:

```bash
# On Windows
set FLASK_APP=app.py
flask run

# On macOS/Linux
export FLASK_APP=app.py
flask run
```

*TODO: Create the main `app.py` file.*

# Development Conventions

*   **Backend:** All backend logic should be implemented in Python using the Flask framework.
*   **Frontend:** All web page content should be written in Korean.
*   **State Management:** Ensure that user inputs are not lost during interaction. This can be managed using server-side sessions or by passing state between requests.
