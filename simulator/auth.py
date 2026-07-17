"""
Rapid7 Nexpose (on-prem InsightVM) authentication: HTTP Basic Auth.

The integration sends `auth=(username, password)` and, if a 2FA Token is
configured, adds a `Token: <2fa>` header. The simulator accepts the token
header but doesn't validate it.
"""
from functools import wraps

from flask import jsonify, request

from config import Config


def require_basic_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if (
            not auth
            or auth.username != Config.AUTH_USERNAME
            or auth.password != Config.AUTH_PASSWORD
        ):
            return (
                jsonify({
                    'status': 401,
                    'message': 'Invalid credentials (check Username and Password).',
                }),
                401,
                {'WWW-Authenticate': 'Basic realm="Nexpose"'},
            )
        return f(*args, **kwargs)
    return decorated
