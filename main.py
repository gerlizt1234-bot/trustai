#!/usr/bin/env python3
"""
TrustAI – Real Security Scanner Backend
"""

import hashlib
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="TrustAI Scanner", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


class ScanRequest(BaseModel):
    url: str
    project_name: str | None = None


class Finding(BaseModel):
    severity: str
    title: str
    title_he: str
    description: str
    description_he: str
    evidence: str
    remediation: str
    remediation_he: str


SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "x-xss-protection": "X-XSS-Protection",
}

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", "API Key"),
    (r"(?i)(secret[_-]?key|secret)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]", "Secret Key"),
    (r"(?i)(access[_-]?token|accessToken)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{20,})['\"]", "Access Token"),
    (r"(?i)(supabase[_-]?(anon|service)[_-]?key)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{20,})['\"]", "Supabase Key"),
    (r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", "JWT Token"),
    (r"(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*['\"]?(AKIA[0-9A-Z]{16})['\"]?", "AWS Access Key"),
    (r"(?i)(private[_-]?key)\s*[:=]\s*['\"]-----BEGIN", "Private Key"),
    (r"(?i)mongodb(\+srv)?://[^\s'\"]+", "MongoDB Connection String"),
    (r"(?i)postgres(ql)?://[^\s'\"]+", "PostgreSQL Connection String"),
]


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


async def fetch_url(client: httpx.AsyncClient, url: str):
    try:
        return await client.get(url, follow_redirects=True, timeout=18.0)
    except Exception:
        return None


def analyze_headers(headers: httpx.Headers) -> list[Finding]:
    findings = []
    missing = [name for key, name in SECURITY_HEADERS.items() if key not in headers]
    if missing:
        findings.append(Finding(
            severity="high",
            title="Missing Security Headers",
            title_he="חסרים Security Headers",
            description=f"Important security headers are missing: {', '.join(missing)}. Increases risk of XSS, clickjacking and protocol downgrade.",
            description_he=f"כותרות אבטחה חשובות חסרות: {', '.join(missing)}. מגביר סיכון ל-XSS, clickjacking והתקפות הורדת פרוטוקול.",
            evidence=f"Missing: {', '.join(missing)}",
            remediation="Configure Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options and Referrer-Policy.",
            remediation_he="הגדר Content-Security-Policy, X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options ו-Referrer-Policy.",
        ))

    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        findings.append(Finding(
            severity="high",
            title="Dangerous CORS Configuration",
            title_he="הגדרת CORS מסוכנת",
            description="Access-Control-Allow-Origin is * while Allow-Credentials is true. This combination is insecure.",
            description_he="Access-Control-Allow-Origin מוגדר ל-* בזמן ש-Credentials מופעל. שילוב לא מאובטח.",
            evidence=f"Allow-Origin: {acao}, Allow-Credentials: {acac}",
            remediation="Whitelist specific trusted origins. Never combine wildcard origin with credentials.",
            remediation_he="הגדר רשימת מקורות מהימנים. לעולם אל תשלב * עם credentials.",
        ))
    elif acao == "*":
        findings.append(Finding(
            severity="medium",
            title="Permissive CORS Policy",
            title_he="מדיניות CORS מתירנית",
            description="Access-Control-Allow-Origin is set to *. Any website can read responses.",
            description_he="Access-Control-Allow-Origin מוגדר ל-*. כל אתר יכול לקרוא תשובות.",
            evidence=f"Access-Control-Allow-Origin: {acao}",
            remediation="Restrict CORS to specific trusted origins.",
            remediation_he="הגבל CORS למקורות מהימנים ספציפיים.",
        ))

    server = headers.get("server", "")
    if server and re.search(r"\d+\.\d+", server):
        findings.append(Finding(
            severity="low",
            title="Server Version Disclosure",
            title_he="חשיפת גרסת שרת",
            description=f"Server header reveals version information: {server}",
            description_he=f"כותרת Server חושפת מידע על גרסה: {server}",
            evidence=f"Server: {server}",
            remediation="Remove or genericize the Server header.",
            remediation_he="הסר או הכליל את כותרת Server.",
        ))
    return findings


def analyze_ssl(hostname: str) -> list[Finding]:
    findings = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                findings.append(Finding(
                    severity="info",
                    title="SSL Certificate Present",
                    title_he="תעודת SSL קיימת",
                    description=f"Valid SSL certificate detected. Expires: {not_after}",
                    description_he=f"זוהתה תעודת SSL תקינה. תוקף עד: {not_after}",
                    evidence=f"Expires: {not_after}",
                    remediation="Ensure automatic certificate renewal is configured.",
                    remediation_he="ודא שחידוש אוטומטי של התעודה מוגדר.",
                ))
    except Exception as e:
        findings.append(Finding(
            severity="high",
            title="SSL/TLS Connection Issue",
            title_he="בעיית חיבור SSL/TLS",
            description=f"Could not establish a secure TLS connection: {str(e)[:120]}",
            description_he=f"לא ניתן היה ליצור חיבור TLS מאובטח: {str(e)[:120]}",
            evidence=str(e)[:200],
            remediation="Verify certificate is valid, not expired, and hostname matches.",
            remediation_he="ודא שהתעודה תקפה, לא פגה, ושהשם תואם.",
        ))
    return findings


def detect_technologies(resp: httpx.Response, soup: BeautifulSoup | None) -> list[str]:
    techs = set()
    headers = {k.lower(): v for k, v in resp.headers.items()}
    text = (resp.text or "").lower()

    server = headers.get("server", "").lower()
    if "cloudflare" in server or "cf-ray" in headers:
        techs.add("Cloudflare")
    if "nginx" in server:
        techs.add("Nginx")
    if "vercel" in headers.get("x-vercel-id", "") or "vercel" in server:
        techs.add("Vercel")
    if "netlify" in server:
        techs.add("Netlify")
    if "x-powered-by" in headers:
        powered = headers["x-powered-by"].lower()
        if "next" in powered:
            techs.add("Next.js")
        if "express" in powered:
            techs.add("Express")

    if "__next_data__" in text or "/_next/" in text:
        techs.add("Next.js")
    if "react" in text or "_jsx" in text:
        techs.add("React")
    if "supabase" in text:
        techs.add("Supabase")
    if "firebase" in text:
        techs.add("Firebase")
    if "tailwind" in text:
        techs.add("Tailwind CSS")
    if "wordpress" in text or "wp-content" in text:
        techs.add("WordPress")
    if "shopify" in text:
        techs.add("Shopify")
    return sorted(techs)


def find_secrets(content: str) -> list[Finding]:
    findings = []
    seen = set()
    for pattern, name in SECRET_PATTERNS:
        for match in re.finditer(pattern, content):
            snippet = match.group(0)[:90]
            key = hashlib.md5(snippet.encode()).hexdigest()
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                severity="critical",
                title=f"Exposed {name} in Client-Side Code",
                title_he=f"{name} חשוף בקוד צד-לקוח",
                description=f"A potential {name} was found in page source or linked JavaScript. Secrets in client-side code can be extracted by anyone.",
                description_he=f"נמצא {name} פוטנציאלי בקוד המקור או ב-JavaScript. Secrets בקוד לקוח ניתנים לחילוץ על ידי כל אחד.",
                evidence=snippet + ("..." if len(match.group(0)) > 90 else ""),
                remediation="Move all secrets to server-side environment variables. Never embed keys or tokens in frontend code.",
                remediation_he="העבר את כל ה-secrets למשתני סביבה בצד השרת. לעולם אל תטמיע מפתחות בקוד Frontend.",
            ))
            if len(findings) >= 6:
                return findings
    return findings


def detect_ai_patterns(content: str, techs: list[str]) -> tuple[list[str], list[str], int]:
    signals_en, signals_he = [], []
    score = 15
    lower = content.lower()

    if "supabase" in techs or "supabase" in lower:
        signals_en.append("Supabase client patterns common in AI-generated apps")
        signals_he.append("דפוסי לקוח Supabase נפוצים באפליקציות שנוצרו עם AI")
        score += 25
    if "next.js" in techs or "__next_data__" in lower:
        signals_en.append("Next.js structure typical of AI builders")
        signals_he.append("מבנה Next.js אופייני לכלי AI")
        score += 15
    if "tailwind" in techs:
        signals_en.append("Heavy Tailwind usage matching popular AI templates")
        signals_he.append("שימוש כבד ב-Tailwind התואם תבניות AI")
        score += 10
    if re.search(r"const\s+handle[A-Z]\w+\s*=\s*async", content):
        signals_en.append("handleXxx async naming frequently generated by LLMs")
        signals_he.append("מוסכמת שמות handleXxx שנפוצה בפלט של מודלים")
        score += 10
    if "todo: implement" in lower or "// todo" in lower:
        signals_en.append("Leftover TODO comments typical of incomplete AI generations")
        signals_he.append("הערות TODO שנשארו – אופייני לייצור AI לא שלם")
        score += 8

    score = min(score, 100)
    if not signals_en:
        signals_en = ["No strong AI-generation signals detected from static analysis"]
        signals_he = ["לא זוהו סימנים חזקים לייצור באמצעות AI מניתוח סטטי"]
    return signals_en, signals_he, score


def calculate_risk_score(findings: list[Finding]) -> tuple[int, str]:
    score = 0
    for f in findings:
        score += {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}.get(f.severity, 0)
    score = min(score, 100)
    if score >= 70:
        label = "High Risk"
    elif score >= 40:
        label = "Medium Risk"
    elif score >= 15:
        label = "Low Risk"
    else:
        label = "Informational"
    return score, label


@app.post("/api/scan")
async def scan(req: ScanRequest):
    url = normalize_url(req.url)
    parsed = urlparse(url)
    if not parsed.hostname:
        raise HTTPException(400, "Invalid URL")

    start = time.time()
    findings: list[Finding] = []
    techs: list[str] = []
    ai_signals_en, ai_signals_he = [], []
    ai_score = 0
    final_url = url
    status_code = None

    async with httpx.AsyncClient(
        headers={"User-Agent": "TrustAI-Security-Scanner/1.0", "Accept": "text/html,application/xhtml+xml"},
        verify=True,
        follow_redirects=True,
    ) as client:
        resp = await fetch_url(client, url)
        if resp is None:
            raise HTTPException(502, "Could not reach the target URL. Make sure it is publicly accessible.")

        final_url = str(resp.url)
        status_code = resp.status_code
        content = resp.text or ""
        soup = BeautifulSoup(content, "lxml") if content else None

        findings.extend(analyze_headers(resp.headers))

        host = parsed.hostname or urlparse(final_url).hostname
        if host and (parsed.scheme == "https" or final_url.startswith("https")):
            findings.extend(analyze_ssl(host))

        techs = detect_technologies(resp, soup)
        findings.extend(find_secrets(content))

        if soup:
            for script in soup.find_all("script", src=True)[:5]:
                src = script.get("src") or ""
                if not src:
                    continue
                try:
                    js_resp = await client.get(urljoin(final_url, src), timeout=8.0)
                    if js_resp.status_code == 200 and len(js_resp.text) < 1_500_000:
                        findings.extend(find_secrets(js_resp.text))
                except Exception:
                    pass

        ai_signals_en, ai_signals_he, ai_score = detect_ai_patterns(content, techs)

        if status_code and status_code >= 500:
            findings.append(Finding(
                severity="medium",
                title="Server Error Response",
                title_he="תשובת שגיאת שרת",
                description=f"Server returned HTTP {status_code}.",
                description_he=f"השרת החזיר HTTP {status_code}.",
                evidence=f"HTTP status: {status_code}",
                remediation="Investigate server logs and avoid leaking internal details in errors.",
                remediation_he="בדוק לוגי שרת והימנע מחשיפת פרטים פנימיים בשגיאות.",
            ))

        if final_url.startswith("https") and soup:
            for tag in soup.find_all(["img", "script", "link"]):
                src = tag.get("src") or tag.get("href") or ""
                if isinstance(src, str) and src.startswith("http://"):
                    findings.append(Finding(
                        severity="medium",
                        title="Mixed Content Detected",
                        title_he="זוהה Mixed Content",
                        description="HTTPS page loads resources over insecure HTTP.",
                        description_he="עמוד HTTPS טוען משאבים דרך HTTP לא מאובטח.",
                        evidence=f"Insecure resource: {src[:100]}",
                        remediation="Serve all resources over HTTPS.",
                        remediation_he="הגש את כל המשאבים דרך HTTPS.",
                    ))
                    break

    risk_score, risk_label = calculate_risk_score(findings)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    return {
        "url": final_url,
        "project_name": req.project_name,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(time.time() - start, 2),
        "status_code": status_code,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "ai_score": ai_score,
        "technologies": techs,
        "ai_signals_en": ai_signals_en,
        "ai_signals_he": ai_signals_he,
        "counts": counts,
        "findings": [f.model_dump() for f in findings],
    }


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "TrustAI Scanner"}


# Serve frontend
if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")

@app.get("/")
async def root():
    index = STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"message": "TrustAI API is running. Frontend not found."}


@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    index = STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    raise HTTPException(404)
