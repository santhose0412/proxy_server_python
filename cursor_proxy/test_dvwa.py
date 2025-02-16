import requests
import time

def test_dvwa_sql_injection():
    proxy = {
        'http': 'http://localhost:8080',
        'https': 'http://localhost:8080'
    }

    # DVWA login details
    login_url = "http://localhost/login.php"
    login_data = {
        "username": "admin",
        "password": "password",
        "Login": "Login"
    }

    # SQL Injection test cases for DVWA
    test_cases = [
        # Basic SQL Injection
        "1' OR '1'='1",
        "' OR 1=1 #",
        "' OR '1'='1",
        
        # DVWA specific payloads
        "' UNION SELECT user,password FROM users #",
        "' UNION SELECT null,user_id FROM users #",
        "admin' #",
        "admin' OR '1'='1' #",
        
        # Advanced SQL Injection
        "' UNION SELECT user,password FROM users WHERE user_id = 1 #",
        "' AND sleep(5) #",
        "' OR sleep(5) #",
        
        # Database information gathering
        "' UNION SELECT null,database() #",
        "' UNION SELECT null,version() #",
        "' UNION SELECT null,user() #"
    ]

    try:
        # First login to DVWA
        session = requests.Session()
        session.proxies = proxy
        
        # Get initial CSRF token
        response = session.get(login_url)
        
        # Login to DVWA
        login_response = session.post(login_url, data=login_data)
        if "Welcome to Damn Vulnerable Web Application" in login_response.text:
            print("Successfully logged into DVWA")
        else:
            print("Failed to login to DVWA")
            return

        # Set security level to low
        session.post("http://localhost/security.php", data={"security": "low", "seclev_submit": "Submit"})

        # Test SQL Injection
        print("\nTesting SQL Injection vulnerabilities:")
        for test in test_cases:
            try:
                # Test GET-based SQL injection
                url = f"http://localhost/vulnerabilities/sqli/?id={test}&Submit=Submit"
                print(f"\nTesting: {test}")
                
                response = session.get(url)
                print(f"Status Code: {response.status_code}")
                
                if response.status_code == 403:
                    print("SQL Injection Detected by Proxy!")
                elif "You have an error in your SQL syntax" in response.text:
                    print("SQL Error Detected in Response!")
                elif "ID:" in response.text and "First name:" in response.text:
                    print("Possible Successful SQL Injection!")
                
                # Add delay between requests
                time.sleep(1)

            except Exception as e:
                print(f"Error during test: {str(e)}")

    except Exception as e:
        print(f"Setup error: {str(e)}")

if __name__ == "__main__":
    test_dvwa_sql_injection() 