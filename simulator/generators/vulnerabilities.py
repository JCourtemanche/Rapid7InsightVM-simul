"""
Deterministic Rapid7 Nexpose vulnerability catalog.

The shape follows the API v3 payload documented in Rapid7's `/vulnerabilities`
endpoint: id (slug), title, description, severity (Critical/Severe/Moderate),
severityScore, cvss.v2/v3, cves, categories, exploits, malwareKits, published,
added, modified, denialOfService, pci, risk.
"""
import random
from datetime import timedelta

from .base import iso_z, past_date


# Real CVE identifiers -> Nexpose-style vulnerability records.
VULN_CATALOG_SEED = [
    ('CVE-2021-44228', 'Apache Log4j Remote Code Execution (Log4Shell)',
     'A remote code execution vulnerability exists in Apache Log4j 2.x when a message is JNDI-lookupable.',
     'Critical', 10.0, ['Apache', 'Remote', 'Web'], 8, 5),
    ('CVE-2024-3400', 'Palo Alto Networks PAN-OS Command Injection',
     'A command injection vulnerability in PAN-OS enables an unauthenticated attacker to execute code as root.',
     'Critical', 10.0, ['Network', 'Firewall'], 6, 2),
    ('CVE-2024-1709', 'ConnectWise ScreenConnect Authentication Bypass',
     'ConnectWise ScreenConnect versions <= 23.9.7 are affected by an authentication bypass vulnerability.',
     'Critical', 10.0, ['Remote Access'], 12, 4),
    ('CVE-2023-46604', 'Apache ActiveMQ Remote Code Execution',
     'Apache ActiveMQ is vulnerable to RCE due to insufficient validation of throwable class type in an OpenWire message.',
     'Critical', 10.0, ['Apache', 'Messaging'], 7, 3),
    ('CVE-2023-4966', 'Citrix NetScaler ADC Buffer Overflow (CitrixBleed)',
     'Sensitive information disclosure in NetScaler ADC/Gateway when configured as a gateway or AAA virtual server.',
     'Critical', 9.4, ['Network', 'Citrix'], 9, 6),
    ('CVE-2023-36884', 'Windows Search Remote Code Execution',
     'Windows Search remote code execution vulnerability, exploited via crafted Office documents.',
     'Severe', 8.8, ['Microsoft', 'Windows'], 3, 1),
    ('CVE-2023-23397', 'Microsoft Outlook Elevation of Privilege',
     'Elevation of privilege via specially crafted email that triggers NTLM authentication.',
     'Critical', 9.8, ['Microsoft', 'Outlook'], 8, 2),
    ('CVE-2023-38831', 'RARLAB WinRAR Code Execution',
     'Code execution via crafted RAR archive that spoofs a file extension.',
     'Severe', 7.8, ['Compression'], 4, 3),
    ('CVE-2023-20198', 'Cisco IOS XE Web UI Privilege Escalation',
     'Vulnerability in the web UI of Cisco IOS XE allows a remote attacker to create an account with level 15 access.',
     'Critical', 10.0, ['Cisco', 'Network'], 5, 1),
    ('CVE-2023-34362', 'Progress MOVEit Transfer SQL Injection',
     'SQL injection vulnerability in the MOVEit Transfer web application.',
     'Critical', 9.8, ['Web', 'File Transfer'], 10, 4),
    ('CVE-2022-30190', 'Microsoft Diagnostic Tool (Follina) Remote Code Execution',
     'Windows Support Diagnostic Tool remote code execution via crafted Office documents.',
     'Severe', 7.8, ['Microsoft', 'Office'], 6, 3),
    ('CVE-2022-22965', 'Spring Framework Remote Code Execution (Spring4Shell)',
     'Spring Framework RCE via data binding, affecting Spring MVC/WebFlux on JDK 9+.',
     'Critical', 9.8, ['Java', 'Spring'], 7, 2),
    ('CVE-2022-26134', 'Atlassian Confluence Server OGNL Injection',
     'OGNL injection allowing unauthenticated RCE on Confluence Server/Data Center.',
     'Critical', 9.8, ['Atlassian', 'Web'], 8, 3),
    ('CVE-2021-34527', 'Windows Print Spooler RCE (PrintNightmare)',
     'Windows Print Spooler improperly performs privileged file operations.',
     'Critical', 8.8, ['Microsoft', 'Windows'], 9, 5),
    ('CVE-2021-26855', 'Microsoft Exchange Server RCE (ProxyLogon)',
     'Microsoft Exchange Server remote code execution via SSRF.',
     'Critical', 9.8, ['Microsoft', 'Exchange'], 11, 6),
    ('CVE-2020-1472', 'Netlogon Elevation of Privilege (Zerologon)',
     'Elevation of privilege in Netlogon Remote Protocol (MS-NRPC).',
     'Critical', 10.0, ['Microsoft', 'AD'], 7, 4),
    ('CVE-2019-19781', 'Citrix ADC Directory Traversal',
     'Directory traversal in Citrix ADC and Gateway.',
     'Critical', 9.8, ['Citrix', 'Network'], 8, 3),
    ('CVE-2019-0708', 'Windows Remote Desktop RCE (BlueKeep)',
     'RDS remote code execution vulnerability when handling connection requests.',
     'Critical', 9.8, ['Microsoft', 'RDP'], 12, 5),
    ('CVE-2017-0144', 'Windows SMB RCE (EternalBlue)',
     'Vulnerabilities in the SMBv1 server allow remote code execution.',
     'Severe', 8.1, ['Microsoft', 'SMB'], 15, 8),
    ('CVE-2024-6387', 'OpenSSH regreSSHion Signal Handler Race Condition',
     'A signal handler race condition in OpenSSH allows unauthenticated remote code execution.',
     'Severe', 8.1, ['SSH', 'Unix'], 3, 0),
    ('CVE-2024-38063', 'Windows TCP/IP Remote Code Execution',
     'Windows TCP/IP RCE vulnerability via crafted IPv6 packets.',
     'Critical', 9.8, ['Microsoft', 'Windows'], 2, 0),
    ('CVE-2023-50164', 'Apache Struts Path Traversal',
     'Path traversal in Apache Struts allowing file upload manipulation to achieve RCE.',
     'Critical', 9.8, ['Apache', 'Java'], 5, 1),
    ('CVE-2024-27198', 'JetBrains TeamCity Authentication Bypass',
     'JetBrains TeamCity authentication bypass allowing admin account creation.',
     'Critical', 9.8, ['CI/CD', 'JetBrains'], 6, 2),
    ('CVE-2024-23917', 'JetBrains TeamCity Authentication Bypass',
     'JetBrains TeamCity authentication bypass in on-premises versions before 2023.11.3.',
     'Critical', 9.8, ['CI/CD', 'JetBrains'], 4, 1),
    ('CVE-2023-6875', 'POST SMTP Mailer WordPress Plugin Authentication Bypass',
     'Authentication bypass in POST SMTP Mailer WordPress plugin.',
     'Critical', 9.8, ['WordPress'], 5, 2),
    ('CVE-2024-21762', 'Fortinet FortiOS Out-of-Bounds Write',
     'Out-of-bounds write vulnerability in FortiOS SSLVPN allowing unauthenticated RCE.',
     'Critical', 9.6, ['Fortinet', 'Network'], 4, 1),
    ('CVE-2023-42917', 'Apple WebKit Memory Corruption',
     'Memory corruption in WebKit allowing arbitrary code execution via crafted web content.',
     'Severe', 8.8, ['Apple', 'WebKit'], 3, 0),
    ('CVE-2016-3189', 'bzip2recover Use-After-Free',
     'Use-after-free vulnerability in bzip2recover allowing denial of service.',
     'Moderate', 6.5, ['Compression'], 1, 0),
    ('CVE-2018-11776', 'Apache Struts 2 RCE',
     'Remote code execution vulnerability in Apache Struts 2 via crafted namespace values.',
     'Severe', 8.1, ['Apache', 'Java'], 8, 4),
    ('CVE-2022-1388', 'F5 BIG-IP iControl REST Authentication Bypass',
     'iControl REST authentication bypass in F5 BIG-IP allowing arbitrary system commands.',
     'Critical', 9.8, ['F5', 'Network'], 7, 3),
    ('CVE-2023-46747', 'F5 BIG-IP TMUI Authentication Bypass',
     'Undisclosed requests may bypass configuration utility authentication.',
     'Critical', 9.8, ['F5', 'Network'], 5, 2),
    ('CVE-2024-4577', 'PHP CGI Argument Injection',
     'PHP-CGI on Windows argument injection allowing RCE.',
     'Critical', 9.8, ['PHP', 'Web'], 6, 1),
    ('CVE-2024-30078', 'Windows Wi-Fi Driver Remote Code Execution',
     'Windows Wi-Fi driver RCE via crafted Wi-Fi packets.',
     'Severe', 8.8, ['Microsoft', 'Wi-Fi'], 1, 0),
    ('CVE-2024-26169', 'Windows Error Reporting Service Elevation of Privilege',
     'Elevation of privilege via WER used by Black Basta ransomware.',
     'Severe', 7.8, ['Microsoft', 'Windows'], 2, 1),
    ('CVE-2023-24880', 'Windows SmartScreen Security Feature Bypass',
     'Security feature bypass in Windows SmartScreen via crafted MOTW.',
     'Moderate', 5.4, ['Microsoft', 'Windows'], 3, 2),
    ('CVE-2022-41040', 'Microsoft Exchange Server SSRF (ProxyNotShell)',
     'Server-side request forgery in Microsoft Exchange, chained with CVE-2022-41082.',
     'Severe', 8.8, ['Microsoft', 'Exchange'], 6, 2),
    ('CVE-2022-41082', 'Microsoft Exchange Server RCE (ProxyNotShell)',
     'RCE in Microsoft Exchange Server via authenticated PowerShell abuse.',
     'Severe', 8.8, ['Microsoft', 'Exchange'], 6, 2),
    ('CVE-2023-3519', 'Citrix ADC & Gateway Unauthenticated RCE',
     'Unauthenticated RCE in Citrix ADC/Gateway when configured as gateway/AAA server.',
     'Critical', 9.8, ['Citrix', 'Network'], 6, 2),
    ('CVE-2024-0204', 'Fortra GoAnywhere MFT Authentication Bypass',
     'Authentication bypass allowing admin user creation in Fortra GoAnywhere MFT.',
     'Critical', 9.8, ['File Transfer'], 5, 2),
    ('CVE-2024-21413', 'Microsoft Outlook Remote Code Execution',
     'Microsoft Outlook RCE via crafted moniker links (MonikerLink).',
     'Critical', 9.8, ['Microsoft', 'Outlook'], 3, 1),
]


def _vuln_id(cve_code, product):
    slug = product.split()[0].lower().replace('/', '-')
    return f"{slug}-{cve_code.lower()}"


def _severity_score(sev):
    return {'Critical': 10, 'Severe': 8, 'Moderate': 5}.get(sev, 5)


def _cvss_v2(score):
    return {
        'accessComplexity': 'L' if score >= 7 else 'M',
        'accessVector': 'N',
        'authentication': 'N' if score >= 8 else 'S',
        'availabilityImpact': 'C' if score >= 7 else 'P',
        'confidentialityImpact': 'C' if score >= 7 else 'P',
        'exploitScore': round(score * 0.4, 2),
        'impactScore': round(score * 0.5, 2),
        'integrityImpact': 'C' if score >= 7 else 'P',
        'score': min(score, 10.0),
        'vector': 'AV:N/AC:L/Au:N/C:C/I:C/A:C',
    }


def _cvss_v3(score):
    return {
        'attackComplexity': 'L' if score >= 8 else 'H',
        'attackVector': 'N',
        'availabilityImpact': 'H' if score >= 7 else 'L',
        'confidentialityImpact': 'H' if score >= 7 else 'L',
        'exploitScore': round(score * 0.4, 2),
        'impactScore': round(score * 0.5, 2),
        'integrityImpact': 'H' if score >= 7 else 'L',
        'privilegeRequired': 'N' if score >= 9 else 'L',
        'scope': 'U',
        'score': score,
        'userInteraction': 'N' if score >= 9.5 else 'R',
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    }


def _risk(cvss3, exploits, mkits):
    return round(cvss3 * 100 + exploits * 25 + mkits * 50, 2)


def build_vulnerability_catalog(count=40):
    catalog = []
    r = random.Random(1337)
    seed = VULN_CATALOG_SEED[:count]
    for idx, (cve, title, desc, sev, cvss3, cats, exploits, mkits) in enumerate(seed):
        published = past_date(min_days=30, max_days=1500)
        added = published + timedelta(days=r.randint(1, 30))
        modified = added + timedelta(days=r.randint(1, 300))
        vid = _vuln_id(cve, cats[0] if cats else 'generic')
        cvss2 = min(10.0, cvss3 * 0.9)
        catalog.append({
            'id': vid,
            'title': title,
            'description': {'html': f'<p>{desc}</p>', 'text': desc},
            'severity': sev,
            'severityScore': _severity_score(sev),
            'cves': [cve],
            'cvss': {'v2': _cvss_v2(cvss2), 'v3': _cvss_v3(cvss3)},
            'riskScore': _risk(cvss3, exploits, mkits),
            'categories': cats,
            'denialOfService': False,
            'exploits': exploits,
            'malwareKits': mkits,
            'pci': {
                'adjustedCVSSScore': int(cvss3),
                'adjustedSeverityScore': _severity_score(sev),
                'fail': cvss3 >= 4.0,
                'status': 'Fail' if cvss3 >= 4.0 else 'Pass',
            },
            'published': iso_z(published),
            'added': iso_z(added),
            'modified': iso_z(modified),
            'links': [
                {'href': f'/api/3/vulnerabilities/{vid}', 'rel': 'self'},
                {'href': f'/api/3/vulnerabilities/{vid}/solutions', 'rel': 'Solutions'},
            ],
        })
    return catalog


def solution_for(vuln):
    """Nexpose /vulnerabilities/{id}/solutions payload."""
    cve = vuln['cves'][0] if vuln['cves'] else vuln['id']
    return {
        'resources': [{
            'id': f'solution-{vuln["id"]}',
            'title': f'Update to patched version for {cve}',
            'summary': {'text': f'Apply the vendor patch for {cve}', 'html': f'<p>Apply the vendor patch for {cve}.</p>'},
            'estimate': 'PT30M',
            'type': 'rollup',
            'appliesTo': vuln['title'],
            'additionalInformation': {
                'text': (
                    f'Follow the {vuln.get("categories", ["vendor"])[0]} advisory to remediate {cve}. '
                    f'Priority is driven by CVSS v3 = {vuln["cvss"]["v3"]["score"]} '
                    f'and {vuln["exploits"]} known exploit(s).'
                ),
            },
        }],
    }
