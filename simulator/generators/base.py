"""
Shared helpers + persona imports for the Rapid7 Nexpose simulator.

Persona data comes from xsiam-shared-personas so the same Business Corp
fleet appears consistently across all XSIAM simulators.
"""
import random
import uuid
from datetime import datetime, timedelta, timezone

from faker import Faker

from xsiam_shared import (
    USERS,
    INTERNAL_IPS,
    MALICIOUS_IPS,
    MALICIOUS_DOMAINS,
    MALICIOUS_URLS,
    MALICIOUS_FILES,
    DOMAIN,
    COMPANY_NAME,
)

fake = Faker()
Faker.seed(2718)
random.seed(2718)


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def now_utc():
    return datetime.now(timezone.utc)


def iso_z(dt=None):
    """Nexpose date format: 2024-05-14T14:42:47.000Z"""
    if dt is None:
        dt = now_utc()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')


def past_date(min_days=1, max_days=365):
    return now_utc() - timedelta(days=random.randint(min_days, max_days))


def generate_guid():
    return str(uuid.uuid4())


def fake_mac():
    return ':'.join(f'{random.randint(0, 255):02X}' for _ in range(6))


# ---------------------------------------------------------------------------
# Nexpose OS fingerprint shapes
# ---------------------------------------------------------------------------

OS_FINGERPRINTS = {
    'Windows 10 Pro': {
        'description': 'Microsoft Windows 10 Pro',
        'family': 'Windows',
        'vendor': 'Microsoft',
        'product': 'Windows 10 Pro',
        'systemName': 'Microsoft Windows',
        'type': 'Workstation',
        'architecture': 'x86_64',
        'version': '10.0',
        'cpe': {'v2.3': 'cpe:2.3:o:microsoft:windows_10:10.0:*:*:*:*:*:*:*', 'part': 'o'},
    },
    'Windows 11 Pro': {
        'description': 'Microsoft Windows 11 Pro',
        'family': 'Windows', 'vendor': 'Microsoft', 'product': 'Windows 11 Pro',
        'systemName': 'Microsoft Windows', 'type': 'Workstation',
        'architecture': 'x86_64', 'version': '11.0',
        'cpe': {'v2.3': 'cpe:2.3:o:microsoft:windows_11:11.0:*:*:*:*:*:*:*', 'part': 'o'},
    },
    'macOS 13 Ventura': {
        'description': 'Apple macOS 13 Ventura',
        'family': 'macOS', 'vendor': 'Apple', 'product': 'macOS Ventura',
        'systemName': 'Apple Mac OS', 'type': 'Workstation',
        'architecture': 'arm64', 'version': '13',
        'cpe': {'v2.3': 'cpe:2.3:o:apple:macos:13:*:*:*:*:*:*:*', 'part': 'o'},
    },
    'macOS 14 Sonoma': {
        'description': 'Apple macOS 14 Sonoma',
        'family': 'macOS', 'vendor': 'Apple', 'product': 'macOS Sonoma',
        'systemName': 'Apple Mac OS', 'type': 'Workstation',
        'architecture': 'arm64', 'version': '14',
        'cpe': {'v2.3': 'cpe:2.3:o:apple:macos:14:*:*:*:*:*:*:*', 'part': 'o'},
    },
    'iOS 17': {
        'description': 'Apple iOS 17',
        'family': 'iOS', 'vendor': 'Apple', 'product': 'iOS 17',
        'systemName': 'Apple iOS', 'type': 'Mobile Device',
        'architecture': 'arm64', 'version': '17',
        'cpe': {'v2.3': 'cpe:2.3:o:apple:ios:17:*:*:*:*:*:*:*', 'part': 'o'},
    },
}

EXTRA_OS = {
    'Ubuntu 22.04 LTS': {
        'description': 'Ubuntu Linux 22.04', 'family': 'Linux',
        'vendor': 'Canonical', 'product': 'Ubuntu Linux',
        'systemName': 'Ubuntu Linux', 'type': 'General',
        'architecture': 'x86_64', 'version': '22.04',
        'cpe': {'v2.3': 'cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*', 'part': 'o'},
    },
    'Ubuntu 20.04 LTS': {
        'description': 'Ubuntu Linux 20.04', 'family': 'Linux',
        'vendor': 'Canonical', 'product': 'Ubuntu Linux',
        'systemName': 'Ubuntu Linux', 'type': 'General',
        'architecture': 'x86_64', 'version': '20.04',
        'cpe': {'v2.3': 'cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:*:*:*:*', 'part': 'o'},
    },
    'Debian 12': {
        'description': 'Debian GNU/Linux 12', 'family': 'Linux',
        'vendor': 'Debian', 'product': 'Debian',
        'systemName': 'Debian Linux', 'type': 'General',
        'architecture': 'x86_64', 'version': '12',
        'cpe': {'v2.3': 'cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*', 'part': 'o'},
    },
    'Windows Server 2019': {
        'description': 'Microsoft Windows Server 2019', 'family': 'Windows',
        'vendor': 'Microsoft', 'product': 'Windows Server 2019',
        'systemName': 'Microsoft Windows', 'type': 'Server',
        'architecture': 'AMD64', 'version': '10.0',
        'cpe': {'v2.3': 'cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*', 'part': 'o'},
    },
    'Windows Server 2022': {
        'description': 'Microsoft Windows Server 2022', 'family': 'Windows',
        'vendor': 'Microsoft', 'product': 'Windows Server 2022',
        'systemName': 'Microsoft Windows', 'type': 'Server',
        'architecture': 'AMD64', 'version': '10.0',
        'cpe': {'v2.3': 'cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*', 'part': 'o'},
    },
    'PAN-OS 10.2': {
        'description': 'Palo Alto Networks PAN-OS 10.2', 'family': 'PAN-OS',
        'vendor': 'Palo Alto Networks', 'product': 'PAN-OS',
        'systemName': 'Palo Alto Networks PAN-OS', 'type': 'Firewall',
        'architecture': 'x86_64', 'version': '10.2',
        'cpe': {'v2.3': 'cpe:2.3:o:paloaltonetworks:pan-os:10.2:*:*:*:*:*:*:*', 'part': 'o'},
    },
}


def os_for_persona(persona):
    return OS_FINGERPRINTS.get(persona['os_name'], OS_FINGERPRINTS['Windows 10 Pro'])


def os_summary(fp):
    return fp.get('description') or fp.get('product') or 'Unknown'


# ---------------------------------------------------------------------------
# Nexpose page envelope
# ---------------------------------------------------------------------------

def page_envelope(items, page=0, size=10, resource_prefix='/api/3/generic'):
    """
    Build Nexpose's standard {resources, page, links} pagination envelope.
    """
    page = max(0, int(page))
    size = max(1, min(int(size), 500))
    total = len(items)
    total_pages = max(1, (total + size - 1) // size)
    start = page * size
    end = start + size
    return {
        'resources': items[start:end],
        'page': {
            'number': page,
            'size': size,
            'totalResources': total,
            'totalPages': total_pages,
        },
        'links': [
            {'href': f'{resource_prefix}?page={page}&size={size}', 'rel': 'self'},
            {'href': f'{resource_prefix}?page={min(total_pages - 1, page + 1)}&size={size}', 'rel': 'next'},
            {'href': f'{resource_prefix}?page=0&size={size}', 'rel': 'first'},
            {'href': f'{resource_prefix}?page={total_pages - 1}&size={size}', 'rel': 'last'},
        ],
    }


def created_response(resource_id):
    """Standard Nexpose POST-create response."""
    return {
        'id': resource_id,
        'links': [{'href': f'#/{resource_id}', 'rel': 'self'}],
    }
