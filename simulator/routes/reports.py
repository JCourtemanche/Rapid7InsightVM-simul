"""
Report endpoints.
  GET  /api/3/report_templates                     - list report templates
  POST /api/3/reports                              - create report (returns Location header)
  POST /api/3/reports/<id>/generate                - trigger a run (returns {id: instance_id})
  GET  /api/3/reports/<id>/history/<inst>          - report run status
  GET  /api/3/reports/<id>/history/<inst>/output   - download the report:
        * format=sql-query        -> CSV (data warehouse style, used by fetch-assets)
        * anything else           -> a tiny placeholder PDF

Stateless by design: gunicorn runs several workers (and Cloud Run several instances),
and the XSIAM collector creates the asset and vulnerability reports concurrently, so
create / generate / history / output for one report often land on different processes.
The report kind (pdf / asset CSV / vulnerability CSV) is therefore encoded in the last
digit of the report id, and every route answers from the id alone. `_REPORTS` is only a
best-effort per-process cache for the list / get routes.
"""
import itertools
import os

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

# Last digit of a report id = report kind (see module docstring)
_KIND_PDF, _KIND_ASSET, _KIND_VULN = 0, 1, 2
# Per-process sequence, offset by pid so concurrent workers rarely hand out the same id
_SEQ = itertools.count(1000 + (os.getpid() % 97) * 10000)


def _new_report_id(fmt, query_type):
    if fmt != 'sql-query':
        kind = _KIND_PDF
    else:
        kind = _KIND_VULN if query_type == 'vulnerability' else _KIND_ASSET
    return next(_SEQ) * 10 + kind


def _report_kind(report_id):
    return report_id % 10


def _instance(report_id):
    return {
        'id': report_id * 10 + 1,
        'status': 'complete',
        'generated': iso_z(),
        'size': {'bytes': 12345, 'formatted': '12.06 KB'},
    }


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
    body = request.get_json(silent=True) or {}
    fmt = body.get('format') or 'pdf'
    query = body.get('query') or ''
    query_type = detect_query_type(query) if fmt == 'sql-query' else None
    report_id = _new_report_id(fmt, query_type)
    report = {
        'id': report_id,
        'name': body.get('name') or f'Report {report_id}',
        'format': fmt,
        'template': body.get('template') or 'audit-report',
        'scope': body.get('scope') or {},
        'query': query,
        'query_type': query_type,
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
    instance = _instance(report_id)
    report = _REPORTS.get(report_id)
    if report is not None:
        report['history'].append(instance)
    return jsonify({'id': instance['id']}), 202


@reports_bp.route('/reports/<int:report_id>/history/<int:instance_id>', methods=['GET'])
@require_basic_auth
def report_history(report_id, instance_id):
    # Reports are generated synchronously: any instance of any report is complete
    return jsonify({**_instance(report_id), 'id': instance_id}), 200


@reports_bp.route('/reports/<int:report_id>/history/<int:instance_id>/output', methods=['GET'])
@require_basic_auth
def report_output(report_id, instance_id):
    kind = _report_kind(report_id)
    if kind in (_KIND_ASSET, _KIND_VULN):
        # Data-warehouse style output used by fetch-assets.
        payload = render_vulnerability_csv() if kind == _KIND_VULN else render_asset_csv()
        return Response(payload, status=200, mimetype='text/csv')

    # Any other format -> return a tiny placeholder PDF.
    body = (
        b'%PDF-1.4\n%Rapid7 Nexpose Simulator - placeholder report output\n'
        + f'%report_id={report_id} instance_id={instance_id}\n'.encode('ascii')
        + b'%%EOF\n'
    )
    return Response(body, status=200, mimetype='application/pdf')
