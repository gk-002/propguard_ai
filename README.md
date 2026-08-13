# PropGuard AI

A civic-safety platform combining three modules behind one authenticated FastAPI backend
and one Flutter app:

1. **Real Estate Scam Detector** — upload a title deed / NOC / sale agreement; the backend runs
   Error Level Analysis (ELA) forensics + OCR, then asks NVIDIA Nemotron for a fraud risk score
   and legal red flags.
2. **WhatsApp/SMS Spam Interceptor** — a native Android `NotificationListenerService` watches
   WhatsApp/SMS notifications, filters locally, and forwards suspicious ones to Nemotron for a
   deeper scam-severity read.
3. **Women's Safety Shield** — an SOS button (or hardware shake trigger) grabs GPS, builds a
   Google Maps link, and fans out SMS alerts to emergency contacts via Twilio.

Authentication is Firebase Auth (Phone OTP or Email/Password) end-to-end: the Flutter app and
the native Kotlin listener both attach a Firebase ID token (JWT) to every backend request; the
FastAPI backend verifies it via the Firebase Admin SDK before doing anything. See **Section 4**.

---

## ⚠️ Can this repo produce an actual `.apk` for you automatically?

**Yes — via GitHub Actions, not by hand.** Compiling a real APK needs the Flutter SDK, Android
SDK, and internet access to pull Gradle/pub dependencies. Push this repo to GitHub, add the
secrets described in **Section 5**, and `.github/workflows/build-apk.yml` will build a real,
installable, signed release APK and attach it to the workflow run as a downloadable artifact —
completely hands-off. Section 5 also gives you the 3 commands to build it locally instead, if
you'd rather not use CI.

---

## 1. Architecture / Directory Tree

```
propguard-ai/
├── docker-compose.yml
├── .gitignore
├── README.md
├── .github/workflows/build-apk.yml     # CI: builds & signs the real Android APK
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── .env.example
│   ├── sql/rls_policies.sql            # Postgres Row-Level Security policies
│   └── app/
│       ├── main.py                     # FastAPI entrypoint: auth, rate limiting, routers
│       ├── auth.py                     # Firebase JWT verification + slowapi rate limiter
│       ├── config.py                   # pydantic-settings env loader
│       ├── database.py                 # async SQLAlchemy engine/session
│       ├── models.py                   # ORM: User, PropertyAudit, InterceptedSpam, SOSLog
│       ├── schemas.py                  # Pydantic request/response contracts
│       ├── security/
│       │   └── encryption.py           # AES-256 field encryption (phone numbers, GPS-adjacent PII)
│       ├── forensics/
│       │   └── ela_detector.py         # Error Level Analysis + EXIF + heatmap
│       ├── services/
│       │   ├── nemotron_client.py      # NVIDIA NIM (OpenAI-compatible) client
│       │   ├── ocr_service.py          # Tesseract OCR + regex field extraction
│       │   ├── twilio_service.py       # SMS dispatch for SOS
│       │   └── keyword_rules.py        # Shared scam keyword list (mirrors Kotlin)
│       └── routers/
│           ├── users.py                # PUT/GET /api/v1/users/me (profile + emergency contacts)
│           ├── property.py             # POST /api/v1/property/audit      [auth required]
│           ├── interceptor.py          # POST /api/v1/interceptor/scan    [auth required]
│           └── sos.py                  # POST /api/v1/sos/trigger         [auth required]
└── mobile/
    ├── android_native/                 # reference-only copy — see SUPERSEDED.md
    └── flutter_app/                    # ← the real, buildable Flutter Android project
        ├── pubspec.yaml
        ├── android/
        │   ├── build.gradle.kts / settings.gradle.kts / gradle.properties
        │   ├── local.properties.example
        │   └── app/
        │       ├── build.gradle.kts         # applicationId, Firebase, signing config
        │       ├── proguard-rules.pro
        │       └── src/main/
        │           ├── AndroidManifest.xml
        │           ├── kotlin/com/propguard/app/
        │           │   ├── MainActivity.kt              # notification_access platform channel
        │           │   └── interceptor/
        │           │       ├── WhatsAppSpamListener.kt   # NotificationListenerService (Module 2)
        │           │       └── LocalAlertDispatcher.kt
        │           └── res/...
        └── lib/
            ├── main.dart                          # Firebase init + auth-gated navigation
            ├── services/
            │   ├── auth_service.dart               # Firebase Auth (Phone OTP + Email/Password)
            │   ├── api_service.dart                # HTTP client — attaches Bearer JWT to every call
            │   └── shake_detector_service.dart      # accelerometer shake -> SOS
            └── screens/
                ├── login_screen.dart
                ├── profile_setup_screen.dart        # emergency contacts onboarding
                ├── property_auditor_screen.dart
                ├── whatsapp_shield_screen.dart
                └── sos_screen.dart
```

---

## 2. Backend Setup

### Prerequisites
- Python 3.12+
- PostgreSQL 16 (or use `docker-compose up db`)
- `tesseract-ocr` and `poppler-utils` system packages (for OCR / PDF pipeline)
- A Firebase project (see Section 4)

### Steps

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env and fill in:
#   - DATABASE_URL
#   - FIREBASE_SERVICE_ACCOUNT_PATH   <-- see Section 4
#   - NVIDIA_API_KEY                  <-- get a fresh key from https://build.nvidia.com/
#   - TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN / TWILIO_FROM_NUMBER
#   - FIELD_ENCRYPTION_KEY            <-- generate per the comment in .env.example
#   - REDIS_URL                       <-- redis://localhost:6379 or "memory://" for solo dev

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Interactive API docs (with an "Authorize" button for pasting a Bearer token): `http://localhost:8000/docs`

### Or via Docker Compose (backend + Postgres in one command)

```bash
cp backend/.env.example backend/.env   # fill in secrets as above
docker compose up --build
```

### ⚠️ About the API key you shared in an earlier chat
If you pasted a live NVIDIA NIM API key into the conversation that generated this blueprint,
**rotate/revoke it** in the NVIDIA `build.nvidia.com` console. Put the new key only in
`backend/.env` (git-ignored), never in source files.

### Production hardening still worth doing
- Replace the dev-mode `init_db()` table creation with proper **Alembic migrations**.
- Wire the RLS `SET LOCAL app.current_uid` pattern from `sql/rls_policies.sql` into
  `app/database.py`'s `get_db()` for defense-in-depth beneath the app-layer filters.
- Put `uploads/` behind access-controlled storage (S3 + signed URLs), not local disk.
- Wire in `pdf2image` for the stubbed PDF branch in `routers/property.py`.
- Point `REDIS_URL` at a real Redis instance before running more than one backend replica —
  otherwise rate limits are per-process, not global.

---

## 3. Mobile Setup (Flutter) — local dev run

```bash
cd mobile/flutter_app
flutter pub get
flutter run --dart-define=API_BASE_URL=http://10.0.2.2:8000   # Android emulator loopback
```

For a physical device, point `API_BASE_URL` at your machine's LAN IP or a deployed backend URL.

---

## 4. Authentication Setup (Firebase)

Per the PRD's auth architecture: Firebase Auth issues short-lived JWTs; the Flutter app and the
native Kotlin listener both attach them as `Authorization: Bearer <token>`; the FastAPI backend
verifies the signature via the Firebase Admin SDK before running any AI/SOS pipeline.

### 4.1 Create the Firebase project
1. Go to the [Firebase Console](https://console.firebase.google.com/) → **Add project**.
2. **Authentication → Sign-in method** → enable **Phone** and **Email/Password**.
3. **Project settings → General → Add app → Android**, package name `com.propguard.app`.
   Download the generated **`google-services.json`** and place it at
   `mobile/flutter_app/android/app/google-services.json` (git-ignored — never commit it).
4. **Project settings → Service accounts → Generate new private key** — this downloads a JSON
   file for the *backend*. Save it as `backend/firebase_key.json` (also git-ignored) and point
   `FIREBASE_SERVICE_ACCOUNT_PATH` at it in `backend/.env`.

### 4.2 How the flow works end-to-end
```
Flutter LoginScreen ──(Phone OTP / Email+Password)──▶ Firebase Auth
       │
       │ AuthService.instance.idToken   (JWT, auto-refreshed)
       ▼
ApiService.* / WhatsAppSpamListener.kt ──Authorization: Bearer <JWT>──▶ FastAPI
       │
       ▼
app/auth.py::get_current_user  — verifies signature via Firebase Admin SDK
       │
       ▼
Routers use the verified `uid` as the only source of identity — no endpoint
trusts a client-supplied user_id.
```

### 4.3 Android Notification Access (Module 2)
`BIND_NOTIFICATION_LISTENER_SERVICE` **cannot** be granted via a runtime permission dialog — the
user must manually enable it. `MainActivity.kt` exposes a `propguard/notification_access`
platform channel; `WhatsAppShieldScreen` calls it to check status and deep-link into:
```kotlin
startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
```

### 4.4 Rate limiting & encryption
- `app/auth.py` wires `slowapi` with Redis-backed storage; `/property/audit` is capped at
  10/hour/user, `/interceptor/scan` at 120/minute/user, `/sos/trigger` at 30/hour/user.
- `app/security/encryption.py` encrypts emergency-contact phone numbers (AES-256 via Fernet)
  before they're written to Postgres, and decrypts them only in-memory right before a Twilio call.
- `backend/sql/rls_policies.sql` adds Postgres Row-Level Security so even a raw DB credential
  leak can't cross user boundaries.

---

## 5. Building the Android APK

### Option A — GitHub Actions (recommended, fully automated)
1. Push this repo to GitHub.
2. **Settings → Secrets and variables → Actions**, add:
   | Secret | Value |
   |---|---|
   | `GOOGLE_SERVICES_JSON` | `base64 -w0 google-services.json` from Section 4.1 |
   | `ANDROID_KEYSTORE_BASE64` *(optional, for a real signed release)* | `base64 -w0 release.jks` |
   | `ANDROID_KEYSTORE_PASSWORD` | your keystore password |
   | `ANDROID_KEY_ALIAS` | your key alias |
   | `ANDROID_KEY_PASSWORD` | your key password |
3. **Settings → Secrets and variables → Actions → Variables**, add `API_BASE_URL` pointing at
   your deployed backend (skip this and it defaults to a placeholder URL you'll want to change).
4. Push to `main`, or trigger manually from the **Actions** tab → *Build PropGuard Android APK* →
   *Run workflow*.
5. Download the `propguard-ai-release-apk` artifact from the completed run — that's your real,
   installable APK.

Generate a release keystore (if you don't have one) with:
```bash
keytool -genkey -v -keystore release.jks -keyalg RSA -keysize 2048 -validity 10000 -alias propguard
```

### Option B — Build locally
Requires the [Flutter SDK](https://docs.flutter.dev/get-started/install) and Android SDK/Android
Studio installed on your machine.

```bash
cd mobile/flutter_app
# 1. Place google-services.json at android/app/google-services.json (Section 4.1)
# 2. (Optional) create android/key.properties for release signing:
cat > android/key.properties <<EOF
storeFile=/absolute/path/to/release.jks
storePassword=yourStorePassword
keyAlias=propguard
keyPassword=yourKeyPassword
EOF

flutter pub get
flutter build apk --release --dart-define=API_BASE_URL=https://your-backend.example.com
# Output: build/app/outputs/flutter-apk/app-release.apk
```

Install on a connected device/emulator: `flutter install`, or copy the APK over and open it
manually (enable "Install unknown apps" for your file manager first).

---

## 6. Twilio SOS Setup (Module 3)

1. Create a Twilio account, buy/verify a sending number.
2. Set `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER` in `backend/.env`.
3. In the app, complete **ProfileSetupScreen** once signed in — this calls
   `PUT /api/v1/users/me` to store up to 5 emergency contacts (encrypted at rest).
4. Test directly against the API (replace `<ID_TOKEN>` with a real Firebase ID token, e.g. copied
   from the Flutter app's debug console or minted via the Firebase Auth REST API):
   ```bash
   curl -X POST http://localhost:8000/api/v1/sos/trigger \
     -H "Authorization: Bearer <ID_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"latitude": 18.5204, "longitude": 73.8567, "trigger_source": "button"}'
   ```

---

## 7. NVIDIA NIM / Nemotron Setup (Modules 1 & 2)

```python
from openai import AsyncOpenAI

client = AsyncOpenAI(
    base_url="https://integrate.api.nvidia.com/v1",
    api_key=settings.nvidia_api_key,   # from .env — never hardcode
)
```

Models used (configurable via `.env`):
- Primary: `nvidia/nemotron-3.5-lightning-30b-a3b`
- Fallback: `nvidia/llama-3.1-nemotron-70b-instruct` (auto-used if primary errors/times out)

Both prompts force strict JSON output — see `app/services/nemotron_client.py`.

---

## 8. Testing the Property Audit Pipeline End-to-End

```bash
curl -X POST http://localhost:8000/api/v1/property/audit \
  -H "Authorization: Bearer <ID_TOKEN>" \
  -F "document_type=title_deed" \
  -F "file=@/path/to/deed_scan.jpg"
```

Response includes `ela_score`, `ela_heatmap_path` (a PNG you can open to see red "hotspot"
regions), OCR-extracted fields, and Nemotron's `fraud_risk_score` / `legal_red_flags` / `ai_summary`.

---

## 9. Known Limitations (call these out to stakeholders)

- PDF upload branch is stubbed (returns 501) pending `pdf2image` wiring.
- The Flutter "Recently Flagged Messages" list uses demo data; wire it to a
  `GET /api/v1/interceptor/history` endpoint (trivial addition mirroring the existing routers).
- ELA is a heuristic signal, not proof of forgery — always position results as "review flags,"
  not a legal verdict, in any user-facing copy.
- App icons/launch screens use Flutter defaults — swap `android/app/src/main/res/mipmap-*` for
  real branded assets before a Play Store release.
- The RLS policy file is provided but not yet wired into `get_db()` — see Section 2's hardening
  checklist; app-layer `WHERE user_id = ...` filters already enforce isolation in the meantime.
