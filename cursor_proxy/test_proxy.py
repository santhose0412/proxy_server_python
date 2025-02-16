import requests
import sys

def test_proxy():
    proxy = {
        'http': 'http://localhost:8080',
        'https': 'http://localhost:8080'
    }

    test_urls = [
        'http://example.com',
        'https://example.com',
        'https://google.com',
        'http://httpbin.org/get',
        'https://httpbin.org/get'
    ]

    for url in test_urls:
        try:
            print(f"\nTesting {url}")
            response = requests.get(url, proxies=proxy, verify=False, timeout=10)
            print(f"Status Code: {response.status_code}")
            print(f"Headers: {dict(response.headers)}")
            print(f"Content Length: {len(response.content)} bytes")
        except Exception as e:
            print(f"Error accessing {url}: {str(e)}")

if __name__ == "__main__":
    test_proxy() 