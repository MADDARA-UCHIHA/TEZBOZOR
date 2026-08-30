"""Production entry point.

Run with a real WSGI server instead of `python app.py` (which uses Flask's
development server) once you're deploying beyond your own machine, e.g.:

    gunicorn -w 4 -b 127.0.0.1:8000 wsgi:app

Put this behind a reverse proxy (nginx) that terminates TLS. Set SECURE_COOKIES=1
and REQUIRE_SECRET_KEY=1 in the environment for that deployment.
"""
from app import app

if __name__ == "__main__":
    app.run()
