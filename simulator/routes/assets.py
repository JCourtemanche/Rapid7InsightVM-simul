"""
Asset endpoints under /api/3/assets.
  GET    /assets                                     - nexpose-get-assets
  POST   /assets/search                              - nexpose-search-assets
  GET    /assets/<id>                                - nexpose-get-asset
  DELETE /assets/<id>                                - nexpose-delete-asset
  GET    /assets/<id>/tags                           - nexpose-get-asset-tags
  GET    /assets/<id>/vulnerabilities                - list vulnerabilities on asset
  GET    /assets/<id>/vulnerabilities/<vid>          - nexpose-get-asset-vulnerability
  GET    /assets/<id>/vulnerabilities/<vid>/solution - solution for a vuln on an asset
"""
from flask import Blueprint, jsonify, request

from auth import require_basic_auth
from generators.assets import (
    asset_summary,
    asset_vulnerability_row,
    asset_vulnerability_solution,
)
from generators.base import page_envelope
from generators.catalog import ASSETS, ASSETS_BY_ID, VULNERABILITIES_BY_ID

from ._helpers import get_pagination


assets_bp = Blueprint('assets', __name__, url_prefix='/api/3/assets')


def _match_search(asset, filters):
    """
    Very light emulation of Nexpose search-DSL. Filters look like:
      [{"field": "host-name", "operator": "contains", "value": "srv"}]
    Supports: host-name, ip-address, os, site-id, risk-score (>=).
    Everything else is ignored and returns True (permissive).
    """
    if not filters:
        return True
    match = filters.get('match', 'all').lower()
    conds = filters.get('filters', [])
    results = []
    for c in conds:
        field = c.get('field', '').lower()
        op = c.get('operator', '').lower()
        value = c.get('value')
        ok = True
        if field == 'host-name':
            ok = str(value or '').lower() in asset['hostName'].lower()
        elif field == 'ip-address':
            ok = str(value or '') == asset['ip']
        elif field == 'os':
            ok = str(value or '').lower() in asset['os'].lower()
        elif field == 'site-id':
            ok = int(value) in asset['sites']
        elif field == 'risk-score':
            try:
                ok = asset['riskScore'] >= float(value)
            except (TypeError, ValueError):
                ok = True
        results.append(ok)
    return all(results) if match == 'all' else any(results)


@assets_bp.route('', methods=['GET'])
@require_basic_auth
def list_assets():
    page, size = get_pagination()
    items = [asset_summary(a) for a in ASSETS]
    return jsonify(page_envelope(items, page, size, '/api/3/assets')), 200


@assets_bp.route('/search', methods=['POST'])
@require_basic_auth
def search_assets():
    body = request.get_json(silent=True) or {}
    filtered = [a for a in ASSETS if _match_search(a, body)]
    items = [asset_summary(a) for a in filtered]
    page, size = get_pagination()
    return jsonify(page_envelope(items, page, size, '/api/3/assets/search')), 200


@assets_bp.route('/<int:asset_id>', methods=['GET'])
@require_basic_auth
def get_asset(asset_id):
    asset = ASSETS_BY_ID.get(asset_id)
    if asset is None:
        return jsonify({'status': 404, 'message': f'Asset {asset_id} not found'}), 404
    return jsonify(asset_summary(asset)), 200


@assets_bp.route('/<int:asset_id>', methods=['DELETE'])
@require_basic_auth
def delete_asset(asset_id):
    if asset_id not in ASSETS_BY_ID:
        return jsonify({'status': 404, 'message': f'Asset {asset_id} not found'}), 404
    return jsonify({'status': 200, 'message': f'Asset {asset_id} deleted'}), 200


@assets_bp.route('/<int:asset_id>/tags', methods=['GET'])
@require_basic_auth
def get_asset_tags(asset_id):
    from generators.catalog import ASSETS_BY_ID
    if asset_id not in ASSETS_BY_ID:
        return jsonify({'status': 404, 'message': f'Asset {asset_id} not found'}), 404
    # Return a small set of stable tags per asset
    tags = [
        {'id': 1, 'name': 'Business Corp', 'type': 'custom', 'links': [{'href': '/api/3/tags/1', 'rel': 'self'}]},
        {'id': 2, 'name': f'site-{ASSETS_BY_ID[asset_id]["sites"][0]}',
         'type': 'location', 'links': [{'href': '/api/3/tags/2', 'rel': 'self'}]},
    ]
    return jsonify(page_envelope(tags, 0, 500, f'/api/3/assets/{asset_id}/tags')), 200


@assets_bp.route('/<int:asset_id>/vulnerabilities', methods=['GET'])
@require_basic_auth
def list_asset_vulnerabilities(asset_id):
    asset = ASSETS_BY_ID.get(asset_id)
    if asset is None:
        return jsonify({'status': 404, 'message': f'Asset {asset_id} not found'}), 404
    rows = [asset_vulnerability_row(asset, v) for v in asset['_vulns']]
    page, size = get_pagination()
    return jsonify(page_envelope(rows, page, size, f'/api/3/assets/{asset_id}/vulnerabilities')), 200


@assets_bp.route('/<int:asset_id>/vulnerabilities/<vuln_id>', methods=['GET'])
@require_basic_auth
def get_asset_vulnerability(asset_id, vuln_id):
    asset = ASSETS_BY_ID.get(asset_id)
    if asset is None:
        return jsonify({'status': 404, 'message': f'Asset {asset_id} not found'}), 404
    vuln = VULNERABILITIES_BY_ID.get(vuln_id)
    if vuln is None or vuln not in asset['_vulns']:
        return jsonify({
            'status': 404,
            'message': f'Vulnerability {vuln_id} not found on asset {asset_id}',
        }), 404
    return jsonify(asset_vulnerability_row(asset, vuln)), 200


@assets_bp.route('/<int:asset_id>/vulnerabilities/<vuln_id>/solution', methods=['GET'])
@require_basic_auth
def get_asset_vulnerability_solution(asset_id, vuln_id):
    asset = ASSETS_BY_ID.get(asset_id)
    if asset is None:
        return jsonify({'status': 404, 'message': f'Asset {asset_id} not found'}), 404
    vuln = VULNERABILITIES_BY_ID.get(vuln_id)
    if vuln is None:
        return jsonify({'status': 404, 'message': f'Vulnerability {vuln_id} not found'}), 404
    return jsonify(asset_vulnerability_solution(asset, vuln)), 200
