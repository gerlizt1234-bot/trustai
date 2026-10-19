# TrustAI – סורק אבטחה אמיתי

## הדרך הכי קלה להעלאה (מהטלפון או מהמחשב)

### אפשרות 1 – Render (מומלץ, חינמי)

1. היכנס ל־https://render.com והתחבר עם Google / GitHub
2. לחץ **New +** → **Web Service**
3. אם יש לך GitHub:
   - העלה את התיקייה `trustai-full` כ-Repository חדש
   - חבר את ה-repo ב-Render
4. הגדרות:
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
5. לחץ **Create Web Service**
6. חכה 2–3 דקות וקבל קישור קבוע

### אפשרות 2 – Railway

1. https://railway.app → התחבר עם GitHub
2. New Project → Deploy from GitHub repo
3. בחר את ה-repo של TrustAI
4. Railway מזהה הכל אוטומטית

### אפשרות 3 – Replit (הכי קל מהאייפון)

1. היכנס ל־https://replit.com
2. Create Repl → Python
3. העלה את כל הקבצים מהתיקייה `trustai-full`
4. ב-Shell הרץ:
   ```
   pip install -r requirements.txt
   uvicorn backend.main:app --host 0.0.0.0 --port 8000
   ```
5. לחץ על כפתור **Webview** / הפעל את ה-Web

---

אחרי ההעלאה תקבל קישור קבוע שעובד מהאייפון עם סריקה אמיתית.
