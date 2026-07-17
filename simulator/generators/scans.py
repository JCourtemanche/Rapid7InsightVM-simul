"""Scan catalog + a small live-scan store for start/stop/pause/resume."""
import random
from datetime import timedelta
from threading import Lock

from .base import iso_z, past_date


HISTORICAL_SCAN_SEED = [
    # scan_id, site_id, site_name, name, status, assets, crit, engine_id
    (5001, 1, 'HQ Paris',       'Weekly Scan HQ',    'finished', 40, 12, 1),
    (5002, 2, 'DR Site',        'Weekly Scan DR',    'finished', 30, 5,  1),
    (5003, 3, 'Cloud Ops',      'Continuous scan',   'running',  25, 3,  1),
    (5004, 4, 'Dev Lab',        'Ad-hoc dev scan',   'finished', 10, 4,  2),
    (5005, 5, 'Remote Workers', 'Agent sweep',       'finished', 55, 8,  1),
    (5006, 1, 'HQ Paris',       'PCI Compliance',    'finished', 60, 15, 1),
    (5007, 3, 'Cloud Ops',      'Emergency scan',    'finished', 20, 6,  1),
    (5008, 1, 'HQ Paris',       'Full audit',        'finished', 90, 22, 2),
]

ENGINES_SEED = [
    (1, 'Rapid7 Cloud Engine', 'engine.rapid7.com', 40894, 'active',   [1, 2, 3, 4, 5]),
    (2, 'HQ Paris Engine',     '192.168.1.100',     40894, 'active',   [1, 4]),
    (3, 'DR Engine',           '10.10.20.5',        40894, 'active',   [2]),
    (4, 'Cloud Agent Engine',  'agent.rapid7.com',  40894, 'active',   [3, 5]),
]


class ScanStore:
    """In-memory store — mirrors the API's ability to keep scan state."""
    def __init__(self, historical):
        self._lock = Lock()
        self._scans = {s['id']: s for s in historical}
        self._next_id = 6000

    def create(self, site_id, name, asset_ids=None):
        with self._lock:
            sid = self._next_id
            self._next_id += 1
            scan = {
                'id': sid,
                'siteId': site_id,
                'siteName': _site_name(site_id),
                'scanName': name or f'Ad-hoc scan {sid}',
                'startTime': iso_z(),
                'endTime': None,
                'duration': None,
                'status': 'running',
                'engineName': 'Rapid7 Cloud Engine',
                'engineId': 1,
                'assets': len(asset_ids or []),
                'vulnerabilities': {'critical': 0, 'severe': 0, 'moderate': 0, 'total': 0},
                'startedBy': 'xsiam-integration',
                'scanType': 'Manual',
                'links': [
                    {'href': f'/api/3/scans/{sid}',       'rel': 'self'},
                    {'href': f'/api/3/scans/{sid}/stop',  'rel': 'Stop Scan'},
                    {'href': f'/api/3/scans/{sid}/pause', 'rel': 'Pause Scan'},
                ],
                'asset_ids': asset_ids or [],
            }
            self._scans[sid] = scan
            return scan

    def _transition(self, sid, target_status):
        with self._lock:
            scan = self._scans.get(int(sid))
            if scan is None:
                return None
            scan['status'] = target_status
            if target_status in ('stopped', 'aborted', 'finished'):
                scan['endTime'] = iso_z()
            return scan

    def stop(self, sid):    return self._transition(sid, 'stopped')
    def pause(self, sid):   return self._transition(sid, 'paused')
    def resume(self, sid):  return self._transition(sid, 'running')

    def get(self, sid):
        return self._scans.get(int(sid))

    def all(self):
        return list(self._scans.values())

    def for_site(self, site_id):
        return [s for s in self._scans.values() if s['siteId'] == int(site_id)]


def _site_name(site_id):
    lookup = {
        1: 'HQ Paris', 2: 'DR Site', 3: 'Cloud Ops',
        4: 'Dev Lab', 5: 'Remote Workers',
    }
    return lookup.get(int(site_id), f'Site {site_id}')


def build_historical_scans():
    scans = []
    r = random.Random(9001)
    for sid, site_id, site_name, name, status, assets, crit, engine_id in HISTORICAL_SCAN_SEED:
        started = past_date(min_days=1, max_days=30)
        duration = r.randint(5, 90)
        ended = None if status == 'running' else started + timedelta(minutes=duration)
        scans.append({
            'id': sid,
            'siteId': site_id,
            'siteName': site_name,
            'scanName': name,
            'startTime': iso_z(started),
            'endTime': iso_z(ended) if ended else None,
            'duration': f'PT{duration}M' if ended else None,
            'status': status,
            'engineName': 'Rapid7 Cloud Engine' if engine_id == 1 else 'HQ Paris Engine',
            'engineId': engine_id,
            'assets': assets,
            'vulnerabilities': {
                'critical': crit,
                'severe': assets * 2,
                'moderate': assets * 3,
                'total': crit + assets * 5,
            },
            'startedBy': r.choice(['scheduler', 'auto', 'admin@business.org']),
            'scanType': 'Scheduled',
            'links': [{'href': f'/api/3/scans/{sid}', 'rel': 'self'}],
        })
    return scans


def build_engines_catalog():
    engines = []
    for eid, name, address, port, status, sites in ENGINES_SEED:
        engines.append({
            'id': eid,
            'name': name,
            'address': address,
            'port': port,
            'contentVersion': '2026-07-01',
            'productVersion': '6.6.293',
            'lastUpdatedDate': iso_z(past_date(1, 30)),
            'lastRefreshedDate': iso_z(past_date(0, 3)),
            'status': status,
            'sites': sites,
            'enginePools': [],
        })
    return engines
