SHAHZAIN TECH - WEB APPLICATION STARTER

Ye learning prototype hai. Is mein:
- User registration aur login
- Password hashing (Werkzeug)
- SQLite database
- User dashboard
- Admin-only page
- CSRF form tokens
- HttpOnly aur SameSite session-cookie settings

TERMUX PAR CHALANE KA TAREEQA

1) ZIP extract karke project folder mein jao.
2) Python aur pip available hon.
3) Commands:

   pkg update
   pkg install python
   cd shahzain-tech-webapp
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt

4) Secret key banao:
   python -c "import secrets; print(secrets.token_hex(32))"

5) Jo key print ho, usay environment mein set karo:
   export SECRET_KEY='YAHAN_APNI_RANDOM_KEY_PASTE_KARO'

6) Admin account create karo:
   python create_admin.py

7) App chalao:
   python app.py

8) Browser mein kholo:
   http://127.0.0.1:5000

IMPORTANT SECURITY LIMITS
- Ye abhi local learning prototype hai, production/high-security website nahi.
- Isay public internet par expose mat karo.
- Production se pehle HTTPS, proper production server, login rate limiting, email verification, password reset, audit logs, secure secret management, database backups, dependency updates, security testing aur privacy/legal review add karna zaroori hai.
- COOKIE_SECURE=1 sirf HTTPS deployment par set karo.
- Admin password kisi ke saath share mat karo.
- Real users ka personal data abhi collect mat karo.
