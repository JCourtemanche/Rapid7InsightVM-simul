"""Rapid7 Nexpose (on-prem InsightVM) API simulator - Flask entrypoint."""
import logging

from flask import Flask, jsonify

from config import Config
from routes.asset_groups import asset_groups_bp
from routes.assets import assets_bp
from routes.reports import reports_bp
from routes.scans import scans_bp
from routes.shared_credentials import shared_creds_bp
from routes.sites import sites_bp
from routes.tags import tags_bp
from routes.vulnerabilities import vulnerabilities_bp
from routes.vulnerability_exceptions import exceptions_bp


def create_app():
    app = Flask(__name__)

    logging.basicConfig(
        level=logging.INFO if Config.DEBUG else logging.WARNING,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )
    logger = logging.getLogger(__name__)
    logger.info('Starting Rapid7 Nexpose API Simulator')

    app.register_blueprint(assets_bp)
    app.register_blueprint(vulnerabilities_bp)
    app.register_blueprint(sites_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(shared_creds_bp)
    app.register_blueprint(exceptions_bp)
    app.register_blueprint(tags_bp)
    app.register_blueprint(asset_groups_bp)
    app.register_blueprint(reports_bp)

    @app.route('/health', methods=['GET'])
    def health():
        return jsonify({
            'status': 'healthy',
            'service': 'Rapid7 Nexpose API Simulator',
            'version': '1.0.0',
        }), 200

    @app.route('/', methods=['GET'])
    def root():
        return jsonify({
            'service': 'Rapid7 Nexpose API Simulator',
            'version': '1.0.0',
            'auth': 'HTTP Basic Auth (username / password)',
            'base_path': '/api/3',
            'endpoints': {
                'GET /api/3/assets': 'List all assets (paginated)',
                'POST /api/3/assets/search': 'Search assets (Nexpose DSL: host-name / ip-address / os / site-id / risk-score)',
                'GET /api/3/assets/<id>': 'Asset detail',
                'GET /api/3/assets/<id>/vulnerabilities': 'Vulnerabilities detected on the asset',
                'GET /api/3/assets/<id>/vulnerabilities/<vid>': 'Single vulnerability on asset',
                'GET /api/3/assets/<id>/vulnerabilities/<vid>/solution': 'Solution for a vuln on an asset',
                'GET /api/3/assets/<id>/tags': 'Tags applied to the asset',
                'GET /api/3/vulnerabilities': 'List all vulnerabilities',
                'GET /api/3/vulnerabilities/<id>': 'Vulnerability detail',
                'GET /api/3/sites': 'List sites',
                'GET /api/3/sites/<id>': 'Site detail',
                'GET /api/3/sites/<id>/assets': 'Assets in a site',
                'POST /api/3/sites/<id>/scans': 'Start a site scan',
                'GET /api/3/sites/<id>/scans': 'List site scans',
                'GET/POST/DELETE /api/3/sites/<id>/site_credentials[/id]': 'Site credentials CRUD',
                'GET/POST/PUT/DELETE /api/3/sites/<id>/scan_schedules[/id]': 'Scan schedules CRUD',
                'GET/POST/DELETE /api/3/sites/<id>/included_targets|excluded_targets|included_asset_groups|excluded_asset_groups': 'Scope',
                'GET /api/3/scans': 'List all scans',
                'GET /api/3/scans/<id>': 'Scan detail',
                'POST /api/3/scans/<id>/stop|pause|resume': 'Scan transitions',
                'GET /api/3/scan_engines': 'List scan engines',
                'GET/POST/PUT/DELETE /api/3/shared_credentials[/id]': 'Shared credentials CRUD',
                'GET/POST/DELETE /api/3/vulnerability_exceptions[/id]': 'Vulnerability exceptions CRUD',
                'POST /api/3/vulnerability_exceptions/<id>/approve|reject|reopen|recall': 'Exception state transitions',
                'GET/POST/PUT/DELETE /api/3/tags[/id]': 'Tags CRUD',
                'GET/POST/DELETE /api/3/tags/<id>/assets|asset_groups': 'Tag membership',
                'GET/POST/PUT/DELETE /api/3/asset_groups[/id]': 'Asset groups CRUD',
                'GET /api/3/report_templates': 'List report templates',
                'POST /api/3/reports': 'Create a report',
                'POST /api/3/reports/<id>/generate': 'Trigger a report run',
                'GET /api/3/reports/<id>/history/<inst>': 'Report run status',
                'GET /api/3/reports/<id>/history/<inst>/output': 'Download the generated report',
                'GET /health': 'Health check (no auth)',
            },
        }), 200

    @app.errorhandler(404)
    def not_found(_):
        return jsonify({'status': 404, 'message': 'Endpoint not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f'Internal server error: {error}')
        return jsonify({'status': 500, 'message': 'Internal server error'}), 500

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
