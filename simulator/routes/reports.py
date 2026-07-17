"""
Report endpoints.
  GET  /api/3/report_templates                     - list report templates
  POST /api/3/reports                              - create report (returns Location header)
  POST /api/3/reports/<id>/generate                - trigger a run (returns {id: instance_id})
  GET  /api/3/reports/<id>/history/<inst>          - report run status
  GET  /api/3/reports/<id>/history/<inst>/output   - download the report:
        * format=sql-query        -> CSV (data warehouse style, used by fetch-assets)
        * anything else           -> a tiny placeholder PDF
"""
from flask import Blueprint, Response, jsonify, request

from auth import require_basic_auth
from generators.base import iso_z, page_envelope
from generators.report_csv import (
    detect_query_type,
    render_asset_csv,
    render_vulnerability_csv,
)

from ._helpers import get_pagination


reports_bp = Blueprint('reports', __name__, url_prefix='/api/3')


TEMPLATES = [
    {'id': 'audit-report',                'name': 'Audit Report',                     'type': 'document', 'built-in': True},
    {'id': 'executive-overview',          'name': 'Executive Overview',               'type': 'document', 'built-in': True},
    {'id': 'top-remediations',            'name': 'Top Remediations',                 'type': 'document', 'built-in': True},
    {'id': 'pci-attestation-of-compliance','name': 'PCI Attestation of Compliance',   'type': 'document', 'built-in': True},
    {'id': 'basic-vuln-check-results',    'name': 'Basic Vulnerability Check Results','type': 'document', 'built-in': True},
]


_REPORTS: dict[int, dict] = {}
_NEXT_ID = 1000
_NEXT_INSTANCE = 5000


@reports_bp.route('/report_templates', methods=['GET'])
@require_basic_auth
def list_templates():
    page, size = get_pagination()
    return jsonify(page_envelope(TEMPLATES, page, size, '/api/3/report_templates')), 200


@reports_bp.route('/reports', methods=['POST'])
@require_basic_auth
def create_report():
    """
    The client MUST see a `Location: /api/3/reports/<id>` header on the 201
    response - the integration extracts the id by splitting the URL on '/'.
    """
    global _NEXT_ID
    body = request.get_json(silent=True) or {}
    _NEXT_ID += 1
    report_id = _NEXT_ID
    fmt = body.get('format') or 'pdf'
    query = body.get('query') or ''
    report = {
        'id': report_id,
        'name': body.get('name') or f'Report {report_id}',
        'format': fmt,
        'template': body.get('template') or 'audit-report',
        'scope': body.get('scope') or {},
        'query': query,
        'query_type': detect_query_type(query) if fmt == 'sql-query' else None,
        'version': body.get('version') or '2.3.0',
        'created': iso_z(),
        'history': [],
    }
    _REPORTS[report_id] = report

    location = f'/api/3/reports/{report_id}'
    return (
        jsonify({
            'id': report_id,
            'links': [{'href': location, 'rel': 'self'}],
        }),
        201,
        {'Location': location},
    )


@reports_bp.route('/reports/<int:report_id>/generate', methods=['POST'])
@require_basic_auth
def generate_report(report_id):
    global _NEXT_INSTANCE
    report = _REPORTS.get(report_id)
    if report is None:
        return jsonify({'status': 404, 'message': f'Report {report_id} not found'}), 404
    _NEXT_INSTANCE += 1
    instance = {
        'id': _NEXT_INSTANCE,
        'status': 'complete',
        'generated': iso_z(),
        'size': {'bytes': 12345, 'formatted': '12.06 KB'},
    }
    report['history'].append(instance)
    return jsonify({'id': _NEXT_INSTANCE}), 202


@reports_bp.route('/reports/<int:report_id>/history/<int:instance_id>', methods=['GET'])
@require_basic_auth
def report_history(report_id, instance_id):
    report = _REPORTS.get(report_id)
    if report is None:
        return jsonify({'status': 404, 'message': f'Report {report_id} not found'}), 404
    inst = next((h for h in report['history'] if h['id'] == instance_id), None)
    if inst is None:
        inst = {
            'id': instance_id,
            'status': 'complete',
            'generated': iso_z(),
            'size': {'bytes': 12345, 'formatted': '12.06 KB'},
        }
    return jsonify(inst), 200


@reports_bp.route('/reports/<int:report_id>/history/<int:instance_id>/output', methods=['GET'])
@require_basic_auth
def report_output(report_id, instance_id):
    report = _REPORTS.get(report_id)
    fmt = (report or {}).get('format') or 'pdf'

    if fmt == 'sql-query':
        # Data-warehouse style output used by fetch-assets.
        qtype = (report or {}).get('query_type') or 'asset'
        payload = render_vulnerability_csv() if qtype == 'vulnerability' else render_asset_csv()
        return Response(payload, status=200, mimetype='text/csv')

    # Any other format -> return a tiny placeholder PDF.
    body = (
        b'%PDF-1.4\n%Rapid7 Nexpose Simulator - placeholder report output\n'
        + f'%report_id={report_id} instance_id={instance_id}\n'.encode('ascii')
        + b'%%EOF\n'
    )
    return Response(body, status=200, mimetype='application/pdf')
