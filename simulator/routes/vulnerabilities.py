"""
Vulnerability endpoints.
  GET /api/3/vulnerabilities        - list all
  GET /api/3/vulnerabilities/<id>   - detail
"""
from flask import Blueprint, jsonify

from auth import require_basic_auth
from generators.base import page_envelope
from generators.catalog import VULNERABILITIES, VULNERABILITIES_BY_ID

from ._helpers import get_pagination


vulnerabilities_bp = Blueprint('vulnerabilities', __name__, url_prefix='/api/3/vulnerabilities')


@vulnerabilities_bp.route('', methods=['GET'])
@require_basic_auth
def list_vulnerabilities():
    page, size = get_pagination()
    return jsonify(page_envelope(VULNERABILITIES, page, size, '/api/3/vulnerabilities')), 200


@vulnerabilities_bp.route('/<vuln_id>', methods=['GET'])
@require_basic_auth
def get_vulnerability(vuln_id):
    v = VULNERABILITIES_BY_ID.get(vuln_id)
    if v is None:
        return jsonify({'status': 404, 'message': f'Vulnerability {vuln_id} not found'}), 404
    return jsonify(v), 200
