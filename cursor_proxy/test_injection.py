import requests
import time

def test_sql_injection():
    proxy = {
        'http': 'http://localhost:8080',
        'https': 'http://localhost:8080'
    }

    # SQL Injection test cases
    test_cases = [
        # Basic SQL Injection
        "1 OR '1'='1'",
        "1; DROP TABLE users;",
        "1 UNION SELECT * FROM users",
        "admin' --",
        "admin' OR '1'='1",
        
        # Advanced SQL Injection
        "1' WAITFOR DELAY '0:0:5'--",
        "1'; EXEC xp_cmdshell 'net user'--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        
        # Blind SQL Injection
        "1' AND '1'='1",
        "1' AND '1'='2",
        
        # Error-based SQL Injection
        "1' AND (SELECT TOP 1 CONCAT(@@version,':',db_name()))<>'",
        
        # Time-based SQL Injection
        "1' AND IF(1=1,SLEEP(5),0)--",
        
        # Union-based SQL Injection
        "1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--",
        
        # Stacked Queries
        "1'; INSERT INTO users VALUES ('hacker','password');--"
    ]

    print("\nTesting GET requests:")
    for test in test_cases:
        try:
            url = f"http://localhost/test?id={test}"
            print(f"\nTesting: {test}")
            response = requests.get(url, proxies=proxy)
            print(f"Status Code: {response.status_code}")
            if response.status_code == 403:
                print("SQL Injection Detected!")
            time.sleep(1)  # Add delay between requests
        except Exception as e:
            print(f"Error: {str(e)}")

    print("\nTesting POST requests:")
    for test in test_cases:
        try:
            url = "http://localhost/login"
            data = {"username": test, "password": "anything"}
            print(f"\nTesting: {test}")
            response = requests.post(url, data=data, proxies=proxy)
            print(f"Status Code: {response.status_code}")
            if response.status_code == 403:
                print("SQL Injection Detected!")
            time.sleep(1)  # Add delay between requests
        except Exception as e:
            print(f"Error: {str(e)}")

if __name__ == "__main__":
    test_sql_injection() 