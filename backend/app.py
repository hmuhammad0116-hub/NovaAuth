import os
import sys
import subprocess

print("===================================")
print("NovaAuth Starting...")
print("===================================")

# Install requirements if needed
try:
    subprocess.check_call([
        sys.executable,
        "-m",
        "pip",
        "install",
        "-r",
        "requirements.txt"
    ])
except Exception as e:
    print("Requirements install warning:", e)

# Get host port
PORT = int(os.environ.get("PORT", 8000))

print(f"Starting FastAPI on port {PORT}")

# Start FastAPI
try:
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        reload=False
    )

except Exception as e:
    print("Startup Error:", e)
    input("Press Enter...")