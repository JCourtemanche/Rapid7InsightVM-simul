"""
CSV emitters for the `format: sql-query` reports used by the fetch-assets
incident flow. Columns match the SQL SELECT statements the integration
posts as its report body (BASE_QUERY_FOR_ASSETS / BASE_QUERY_FOR_VULNERABILITIES).
"""
import csv
import io
import json

from .catalog import ASSETS


ASSET_COLUMNS = [
    'dim_asset.last_assessed_for_vulnerabilities',
    'fact_asset_discovery.last_discovered',
    'dim_asset.asset_id',
    'dim_asset.host_name',
    'dim_asset.host_type_id',
    'dim_host_type.description',
    'ipv4',
    'ipv6',
    'dim_asset.mac_address',
    'dim_asset.sites',
    'dim_asset.operating_system_id',
    'dim_operating_system.architecture',
    'dim_operating_system.description',
    'dim_operating_system.family',
    'dim_operating_system.name',
    'dim_operating_system.system',
    'dim_operating_system.asset_type',
    'dim_operating_system.vendor',
    'dim_operating_system.version',
    'dim_operating_system.cpe',
    'fact_asset_scan_operating_system.certainty',
    'dim_tag_asset.tags',
    'dim_asset_mac_address.mac_address',
    'dim_asset_ip_address.ip_address',
    'asset_files',
    'asset_softwares',
    'dim_scan.finished',
    'dim_scan.status_id',
    'dim_scan.scan_id',
    'dim_scan.started',
    'dim_scan.type_id',
    'dim_scan.scan_name',
    'fact_asset_scan.vulnerabilities',
    'fact_asset_scan.aggregated_credential_status_id',
    'dim_aggregated_credential_status.aggregated_credential_status_description',
    'asset hosts',
    'asset_services',
]


VULN_COLUMNS = [
    'asset_id',
    'vuln_id',
    'scan_id',
    'date',
    'finding_details_json',
    'vulnerability_name',
    'vulnerability_severity',
    'title',
    'description',
    'date_published',
    'date_added',
    'severity_score',
    'riskscore',
    'cvss_authentication_id',
    'cvss_exploit_score',
    'cvss_impact_score',
    'cvss_v2_score',
    'cvss_v2_exploit_score',
    'cvss_v2_impact_score',
    'cvss_v3_score',
    'cvss_v3_exploit_score',
    'denial_of_service',
    'exploits',
    'malware_kits',
    'date_modified',
    'vuln_categories',
    'aggregated_cves',
]


def _asset_row(asset):
    fp = asset['osFingerprint']
    softwares = [
        {'Software_ID': i + 1, 'Vendor': fp.get('vendor'), 'Family': fp.get('family'),
         'Name': fp.get('product'), 'Version': fp.get('version'),
         'Software_class': 'operating-system', 'Cpe': fp.get('cpe', {}).get('v2.3')}
        for i in range(1)
    ]
    tags = [
        {'Name': 'Business Corp', 'Type': 'custom'},
        {'Name': f'site-{asset["sites"][0]}', 'Type': 'location'},
    ]
    services = [
        {'Name': s['name'], 'Port': s['port'], 'Product': s['product'], 'Protocol': s['protocol']}
        for s in asset.get('services', [])
    ]
    ip = asset['ip']
    ipv4 = ip if ':' not in ip else ''
    ipv6 = ip if ':' in ip else ''
    return {
        'dim_asset.last_assessed_for_vulnerabilities': asset['lastAssessedForVulnerabilities'],
        'fact_asset_discovery.last_discovered': asset['lastAssessedForVulnerabilities'],
        'dim_asset.asset_id': asset['id'],
        'dim_asset.host_name': asset['hostName'],
        'dim_asset.host_type_id': 1 if asset['type'] == 'workstation' else 2,
        'dim_host_type.description': asset['type'].title(),
        'ipv4': ipv4,
        'ipv6': ipv6,
        'dim_asset.mac_address': asset['mac'],
        'dim_asset.sites': ','.join(str(s) for s in asset['sites']),
        'dim_asset.operating_system_id': hash(fp.get('cpe', {}).get('v2.3', 'unknown')) & 0xFFFF,
        'dim_operating_system.architecture': fp.get('architecture'),
        'dim_operating_system.description': fp.get('description'),
        'dim_operating_system.family': fp.get('family'),
        'dim_operating_system.name': fp.get('product'),
        'dim_operating_system.system': fp.get('systemName'),
        'dim_operating_system.asset_type': fp.get('type'),
        'dim_operating_system.vendor': fp.get('vendor'),
        'dim_operating_system.version': fp.get('version'),
        'dim_operating_system.cpe': fp.get('cpe', {}).get('v2.3'),
        'fact_asset_scan_operating_system.certainty': 1.0,
        'dim_tag_asset.tags': json.dumps(tags),
        'dim_asset_mac_address.mac_address': json.dumps([asset['mac']]),
        'dim_asset_ip_address.ip_address': json.dumps([ip]),
        'asset_files': json.dumps([]),
        'asset_softwares': json.dumps(softwares),
        'dim_scan.finished': asset['lastScanEnd'],
        'dim_scan.status_id': 'C',
        'dim_scan.scan_id': 5000,
        'dim_scan.started': asset['lastScanStart'],
        'dim_scan.type_id': 'S',
        'dim_scan.scan_name': 'Weekly Scan',
        'fact_asset_scan.vulnerabilities': asset['vulnerabilities']['total'],
        'fact_asset_scan.aggregated_credential_status_id': 'C',
        'dim_aggregated_credential_status.aggregated_credential_status_description': 'Credentials worked',
        'asset hosts': json.dumps([asset['hostName']]),
        'asset_services': json.dumps(services),
    }


def _vuln_row(asset, vuln):
    finding_details = [{
        'status_id': 'V',
        'proof': f'Vulnerable to {vuln["id"]}',
        'service_id': 0,
        'port': 0,
        'protocol_id': 'tcp',
    }]
    cats = [{'id': i + 1, 'name': c} for i, c in enumerate(vuln.get('categories', []))]
    return {
        'asset_id': asset['id'],
        'vuln_id': vuln['id'],
        'scan_id': 5000,
        'date': asset['lastAssessedForVulnerabilities'],
        'finding_details_json': json.dumps(finding_details),
        'vulnerability_name': vuln['id'],
        'vulnerability_severity': vuln['severity'],
        'title': vuln['title'],
        'description': vuln['description']['text'],
        'date_published': vuln['published'],
        'date_added': vuln['added'],
        'severity_score': vuln['severityScore'],
        'riskscore': vuln['riskScore'],
        'cvss_authentication_id': vuln['cvss']['v2']['authentication'],
        'cvss_exploit_score': vuln['cvss']['v2']['exploitScore'],
        'cvss_impact_score': vuln['cvss']['v2']['impactScore'],
        'cvss_v2_score': vuln['cvss']['v2']['score'],
        'cvss_v2_exploit_score': vuln['cvss']['v2']['exploitScore'],
        'cvss_v2_impact_score': vuln['cvss']['v2']['impactScore'],
        'cvss_v3_score': vuln['cvss']['v3']['score'],
        'cvss_v3_exploit_score': vuln['cvss']['v3']['exploitScore'],
        'denial_of_service': vuln['denialOfService'],
        'exploits': vuln['exploits'],
        'malware_kits': vuln['malwareKits'],
        'date_modified': vuln['modified'],
        'vuln_categories': json.dumps(cats),
        'aggregated_cves': ', '.join(vuln['cves']),
    }


def _write_csv(columns, rows):
    buf = io.StringIO(newline='')
    writer = csv.DictWriter(buf, fieldnames=columns, quoting=csv.QUOTE_MINIMAL)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue().encode('utf-8')


def render_asset_csv():
    """Emit the CSV that BASE_QUERY_FOR_ASSETS would produce."""
    rows = [_asset_row(a) for a in ASSETS]
    return _write_csv(ASSET_COLUMNS, rows)


def render_vulnerability_csv():
    """Emit the CSV that BASE_QUERY_FOR_VULNERABILITIES would produce."""
    rows = []
    for a in ASSETS:
        for v in a['_vulns']:
            rows.append(_vuln_row(a, v))
    return _write_csv(VULN_COLUMNS, rows)


def detect_query_type(query):
    """
    Return 'vulnerability' or 'asset' based on the SQL body posted by the
    integration. `dim_vulnerability` only appears in the vuln query.
    """
    q = (query or '').lower()
    if 'dim_vulnerability' in q or 'vulnerability_id' in q:
        return 'vulnerability'
    return 'asset'
