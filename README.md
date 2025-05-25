# Mini vulnerability scanner

## Project description

This project was created as part of my journey to learn more about Python and my interest in cybersecurity. The goal was to create a simple tool that can perform basic vulnerability scanning on websites and integrate external APIs to gather additional security information.

## What does this project do?

- **XSS vulnerability scanning:**  
  Tests a given URL for possible Cross-Site Scripting (XSS) vulnerabilities using predefined payloads.

- **VirusTotal API Integration:**  
  Gets a detailed security report on the URL from VirusTotal, which aggregates data from various antivirus and security services.

- **Simple GUI:**  
  Provides a graphical user interface created using the [Flet](https://flet.dev/) library that allows users to enter URLs, run scans, and view results in a clear and user-friendly manner.

## Technologies and concepts used

- Python 3.x  
- Object Oriented Programming (OOP) - modular code with classes  
- Unit tests to ensure code reliability  
- Working with external APIs (VirusTotal)  
- Dependency management via `requirements.txt` file  
- Secure API key handling with `.env` file  
- GUI development using Flet  

## How to Use

1. Clone the repository and create a virtual environment:  
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/MacOS
   venv\Scripts\activate     # Windows

2. Install dependencies:
    ```bash
    pip install -r requirements.txt

3. Create a .env file in the project folder containing your VirusTotal API key:
    ```bash
    VT_API_KEY=your_virustotal_api_key

4. Run the GUI application:
   ```bash
   python gui.py

5. Enter the URL you want to scan and start the scan.


