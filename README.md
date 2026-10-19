# TrustAI - Render Upload Version

## איך להעלות ל-Render

1. New + → Web Service
2. בחר Upload files
3. העלה את כל הקבצים האלה (באותה רמה):
   - main.py
   - requirements.txt
   - Procfile
   - תיקיית static/ (עם index.html בתוכה)

4. הגדרות:
   Build Command:  pip install -r requirements.txt
   Start Command:  uvicorn main:app --host 0.0.0.0 --port $PORT

5. Create Web Service
