import re
from bs4 import BeautifulSoup

def read_html(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()

def detect_sql_injection(query_string):
    sql_patterns = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|EXEC|TRUNCATE)\b)",
        r"(--+)",
        r"(;+)",
        r"('|\")",
        r"(\bOR\b.*=.*)",
        r"(\bAND\b.*=.*)",
        r"(/\*.*\*/)",
        r"\b(CONCAT|CHAR|SUBSTRING|ASCII|BIN|HEX|UNHEX|BASE64)\b",
        r"\b(SLEEP|BENCHMARK|WAIT FOR DELAY)\b",
        r"\b(INFORMATION_SCHEMA|SYSUSERS|SYSOBJECTS)\b",
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, query_string, re.IGNORECASE):
            return True
    return False

def analyze_html(file_path):
    html_content = read_html(file_path)
    soup = BeautifulSoup(html_content, 'html.parser')
    injection_points = []

    forms = soup.find_all('form')
    for form in forms:
        inputs = form.find_all('input', {'type': 'text'})
        for input_tag in inputs:
            value = input_tag.get('value', '')
            if detect_sql_injection(value):
                injection_points.append(value)
    
    return injection_points

if __name__ == "__main__":
    html_file = "test_dvwa.html"  # Replace with your actual HTML file path
    injection_points = analyze_html(html_file)
    
    if injection_points:
        print("Potential SQL Injection Points Detected:")
        for point in injection_points:
            print(point)
    else:
        print("No SQL Injection Points Detected.")