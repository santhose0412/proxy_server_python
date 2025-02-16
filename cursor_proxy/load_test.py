import concurrent.futures
import requests
import time

def make_request(url):
    proxies = {
        'http': 'http://localhost:8080',
        'https': 'http://localhost:8080'
    }
    return requests.get(url, proxies=proxies)

def load_test(concurrent_requests=10):
    urls = [
        'http://example.com',
        'https://example.com',
        'http://example.com/page?id=1',
        'https://example.com/page?id=1'
    ]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_requests) as executor:
        future_to_url = {executor.submit(make_request, url): url for url in urls * 25}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                response = future.result()
                print(f"{url}: {response.status_code}")
            except Exception as e:
                print(f"{url}: {str(e)}")

if __name__ == "__main__":
    load_test() 