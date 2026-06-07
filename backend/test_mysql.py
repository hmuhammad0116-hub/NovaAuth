import requests

API = "http://127.0.0.1:8000"

ADMIN_HEADERS = {
    "X-Admin-Secret": "NovaAuth_Admin_Secret_2026_ChangeMe"
}


def show(name, r):
    print("\n====", name, "====")
    print("STATUS:", r.status_code)
    print("TEXT:", r.text)

    try:
        print("JSON:", r.json())
    except Exception:
        print("JSON: failed")

    return r


r = show("CREATE APP WITHOUT ADMIN", requests.post(
    f"{API}/api/v1/admin/create-app",
    json={
        "name": "No Admin Test",
        "version": "1.0.0"
    }
))

r = show("CREATE APP WITH ADMIN", requests.post(
    f"{API}/api/v1/admin/create-app",
    json={
        "name": "Test App",
        "version": "1.0.0"
    },
    headers=ADMIN_HEADERS
))

app_id = r.json()["app_id"]
app_secret = r.json()["app_secret"]

r = show("CREATE LICENSE WITH ADMIN", requests.post(
    f"{API}/api/v1/admin/create-license",
    params={
        "app_id": app_id,
        "duration_days": 30
    },
    headers=ADMIN_HEADERS
))

license_key = r.json()["license_key"]

r = show("REGISTER", requests.post(
    f"{API}/api/v1/register",
    json={
        "app_id": app_id,
        "app_secret": app_secret,
        "username": "testuser_admin_secure",
        "password": "123456",
        "license_key": license_key,
        "hwid": "TEST-PC-001"
    }
))

token = r.json().get("token")

r = show("VALIDATE", requests.post(
    f"{API}/api/v1/validate",
    json={
        "token": token,
        "hwid": "TEST-PC-001"
    }
))

r = show("LOGOUT", requests.post(
    f"{API}/api/v1/logout",
    json={
        "token": token
    }
))

r = show("VALIDATE AFTER LOGOUT", requests.post(
    f"{API}/api/v1/validate",
    json={
        "token": token,
        "hwid": "TEST-PC-001"
    }
))