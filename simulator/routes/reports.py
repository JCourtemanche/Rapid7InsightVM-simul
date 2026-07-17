"""
Report endpoints (minimal).
  GET  /api/3/report_templates                                 - list report templates
  POST /api/3/reports                                          - create report
  POST /api/3/reports/<id>/generate                            - trigger a report run
  GET  /api/3/reports/<id>/history/<inst>                      - report run status
  GET  /api/3/reports/<id>/history/<inst>/output               - download report (dummy)
"""
from flask import Blueprint, Response, jsonify, request

from auth import require_basic_auth
from generators.base import created_response, iso_z, page_envelope

from ._helpers import get_pagination


reports_bp = Blueprint('reports', __name__, url_prefix='/api/3')


TEMPLATES = [
    {'id': 'audit-report', 'name': 'Audit Report', 'type': 'document', 'built-in': True},
    {'id': 'executive-overview', 'name': 'Executive Overview', 'type': 'document', 'built-in': True},
    {'id': 'top-remediations', 'name': 'Top Remediations', 'type': 'document', 'built-in': True},
    {'id': 'pci-attestation-of-compliance', 'name': 'PCI Attestation of Compliance',
     'type': 'document', 'built-in': True},
    {'id': 'basic-vuln-check-results', 'name': 'Basic Vulnerability Check Results',
     'type': 'document', 'built-in': True},
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
    global _NEXT_ID
    body = request.get_json(silent=True) or {}
    _NEXT_ID += 1
    _REPORTS[_NEXT_ID] = {
        'id': _NEXT_ID,
        'name': body.get('name') or f'Report {_NEXT_ID}',
        'format': body.get('format') or 'pdf',
        'template': body.get('template') or 'audit-report',
        'scope': body.get('scope') or {},
        'created': iso_z(),
        'history': [],
    }
    return jsonify(created_response(_NEXT_ID)), 201


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
        # Fabricate a complete run so downstream can move on.
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
    # Return a tiny PDF-ish placeholder so the download step succeeds.
    body = (
        b'%PDF-1.4\n%Rapid7 Nexpose Simulator - placeholder report output\n'
        + f'%report_id={report_id} instance_id={instance_id}\n'.encode('ascii')
        + b'%%EOF\n'
    )
    return Response(body, status=200, mimetype='application/pdf')
