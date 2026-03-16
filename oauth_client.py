"""
Authlib OAuth client configuration for Google Sign-In.
"""

import os
from authlib.integrations.flask_client import OAuth

oauth = OAuth()


def init_oauth(app):
    """
    Initialize Authlib OAuth with Google OpenID configuration.
    """
    oauth.init_app(app)

    client_id = app.config.get("GOOGLE_CLIENT_ID") or os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = app.config.get("GOOGLE_CLIENT_SECRET") or os.environ.get(
        "GOOGLE_CLIENT_SECRET"
    )

    # If not configured, we still register the client with empty values so that
    # route handlers can detect missing configuration and fail gracefully.
    oauth.register(
        name="google",
        client_id=client_id,
        client_secret=client_secret,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )

