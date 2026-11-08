# AI Web Threat Detection Backend

## Open in Visual Studio Code
1. Extract `web_threat_detection_backend.zip`.
2. Open VS Code.
3. Select **File -> Open Folder** and choose `web_threat_backend`.
4. Open **Terminal -> New Terminal**.

## Install Python packages
```bash
python -m venv .venv
```

Windows PowerShell:
```powershell
.venv\Scripts\Activate.ps1
```

Windows Command Prompt:
```bat
.venv\Scripts\activate.bat
```

macOS/Linux:
```bash
source .venv/bin/activate
```

Then install:
```bash
python -m pip install -r requirements.txt
```

## Start the API
```bash
python -m uvicorn app:app --reload
```

Open:
- API documentation: http://127.0.0.1:8000/docs
- Health check: http://127.0.0.1:8000/health

## Test a URL
In `/docs`, expand **POST /scan**, click **Try it out**, and enter:
```json
{
  "url": "https://example.com"
}
```
Click **Execute**.

## Report a suspicious URL
Use **POST /report**:
```json
{
  "url": "https://example.com/login",
  "reason": "Suspicious login page"
}