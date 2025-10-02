# Project Overview

This project aims to create an interactive web application to demonstrate and experiment with the AES (Advanced Encryption Standard) algorithm. The application will be built using Python and the Streamlit framework.

The primary goal is to provide an educational tool that visualizes the inner workings of AES, including key expansion, round-by-round encryption, and the mathematical operations involved in each step (SubBytes, ShiftRows, MixColumns). The user interface and all content will be in Korean.

## Key Features

*   **Interactive UI:** A web-based interface allowing users to select AES key sizes (128, 196, 256).
*   **Step-by-Step Visualization:** Detailed explanations and visualizations for each component of the AES algorithm.
*   **Calculators:** Tools to perform calculations related to GF(2^8) arithmetic and other AES transformations.
*   **Educational Content:** Pages dedicated to the history of AES, the avalanche effect, and various cryptanalysis methods.
*   **Core Technologies:**
    *   **Language:** Python
    *   **Framework:** Streamlit

# Building and Running

1.  **Prerequisites:**
    *   Python 3.7+
    *   pip (Python package installer)

2.  **Installation:**
    It is recommended to create a virtual environment first.

    ```bash
    # Create and activate a virtual environment (optional but recommended)
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`

    # Install required libraries
    pip install streamlit
    # TODO: Add other libraries like cryptography as they are used.
    ```

3.  **Running the Application:**
    Create a main Python file (e.g., `app.py`) and run the following command in your terminal:

    ```bash
    streamlit run app.py
    ```

# Development Conventions

*   **Main File:** The main Streamlit application entry point should be `app.py`.
*   **Language:** All user-facing text and comments should be in Korean.
*   **Structure:** The application should be organized into multiple pages/tabs as outlined in the `README.md` to maintain clarity and separation of concerns.
*   **State Management:** The application state (like the selected key size) should be managed using Streamlit's session state to ensure consistency across pages. Changing the key size should reset the state of all pages.
