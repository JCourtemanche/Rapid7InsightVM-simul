# Rapid7 Nexpose / InsightVM (on-prem) API Simulator

Simulateur de l'API Rapid7 Nexpose / InsightVM on-premise pour tester et démontrer l'intégration Cortex XSIAM **Rapid7 InsightVM** (basée sur le pack `Rapid7_Nexpose`) sans avoir accès à une console Nexpose/InsightVM réelle.

> Bien que le pack XSIAM s'appelle "Rapid7 Nexpose" (identifiant historique de l'outil), la version affichée est bien **Rapid7 InsightVM** — ce simulateur reproduit l'API v3 utilisée par les deux (endpoint `/api/3/...`).

Basé sur [xsiam-simulator-template](https://github.com/JCourtemanche/xsiam-simulator-template) et le package partagé [xsiam-shared-personas](https://github.com/JCourtemanche/xsiam-shared-personas) — les mêmes utilisateurs, hostnames et IPs Business Corp apparaissent à travers tous les simulateurs.

## Auth

**HTTP Basic Auth** (username + password), plus un header optionnel `Token: <2fa>` accepté mais non validé.

## Base URL

`<server>/api/3/...`

## Réponses

Standard Nexpose : les listes utilisent l'enveloppe `{resources, page, links}` avec `page.{number, size, totalResources, totalPages}`.

## Endpoints couverts

### Assets
| Méthode | Endpoint | Commande XSIAM |
|---|---|---|
| GET | `/api/3/assets` | `nexpose-get-assets` |
| POST | `/api/3/assets/search` | `nexpose-search-assets` |
| GET | `/api/3/assets/<id>` | `nexpose-get-asset` |
| DELETE | `/api/3/assets/<id>` | `nexpose-delete-asset` |
| GET | `/api/3/assets/<id>/tags` | `nexpose-get-asset-tags` |
| GET | `/api/3/assets/<id>/vulnerabilities` | (utilisé implicitement) |
| GET | `/api/3/assets/<id>/vulnerabilities/<vid>` | `nexpose-get-asset-vulnerability` |
| GET | `/api/3/assets/<id>/vulnerabilities/<vid>/solution` | (solution associée) |

Le search DSL supporte : `host-name`, `ip-address`, `os`, `site-id`, `risk-score` (autres champs → permissif).

### Vulnerabilities
| Méthode | Endpoint | Commande XSIAM |
|---|---|---|
| GET | `/api/3/vulnerabilities` | `nexpose-list-vulnerability` |
| GET | `/api/3/vulnerabilities/<id>` | (détail) |

### Sites (+ scans, credentials, schedules, targets, groupes)
| Méthode | Endpoint | Commande XSIAM |
|---|---|---|
| GET/POST/DELETE | `/api/3/sites[/<id>]` | `nexpose-get-sites`, `nexpose-create-site`, `nexpose-delete-site` |
| GET/POST | `/api/3/sites/<id>/assets` | `nexpose-create-asset` |
| GET/POST | `/api/3/sites/<id>/scans` | `nexpose-start-site-scan` |
| GET/POST | `/api/3/sites/<id>/site_credentials` | `nexpose-list-site-scan-credential`, `nexpose-create-site-scan-credential` |
| PUT/DELETE | `/api/3/sites/<id>/site_credentials/<cid>` | `nexpose-update-site-scan-credential`, `nexpose-delete-site-scan-credential` |
| POST | `/api/3/sites/<id>/shared_credentials` | `nexpose-list-assigned-shared-credential` |
| PUT | `/api/3/sites/<id>/shared_credentials/<cid>/enabled` | `nexpose-enable-shared-credential`, `nexpose-disable-shared-credential` |
| GET/POST | `/api/3/sites/<id>/scan_schedules` | `nexpose-list-scan-schedule`, `nexpose-create-scan-schedule` |
| PUT/DELETE | `/api/3/sites/<id>/scan_schedules/<sid>` | `nexpose-update-scan-schedule`, `nexpose-delete-scan-schedule` |
| GET/POST/DELETE | `/api/3/sites/<id>/included_targets` \| `excluded_targets` \| `included_asset_groups` \| `excluded_asset_groups` | `nexpose-{list,add,remove}-site-{included,excluded}-{asset,asset-group}` |

### Scans (top-level)
| Méthode | Endpoint | Commande XSIAM |
|---|---|---|
| GET | `/api/3/scans` | `nexpose-get-scans` |
| GET | `/api/3/scans/<id>` | `nexpose-get-scan` |
| POST | `/api/3/scans` | `nexpose-start-assets-scan` |
| POST | `/api/3/scans/<id>/stop\|pause\|resume` | `nexpose-{stop,pause,resume}-scan` |
| GET | `/api/3/scan_engines` | (utilisé par les playbooks) |

### Shared Credentials
| GET/POST | `/api/3/shared_credentials` | `nexpose-list-shared-credential`, `nexpose-create-shared-credential` |
| GET/PUT/DELETE | `/api/3/shared_credentials/<id>` | `nexpose-update-shared-credential`, `nexpose-delete-shared-credential` |

### Vulnerability Exceptions
| GET/POST | `/api/3/vulnerability_exceptions` | `nexpose-list-vulnerability-exceptions`, `nexpose-create-vulnerability-exception` |
| GET/DELETE | `/api/3/vulnerability_exceptions/<id>` | `nexpose-delete-vulnerability-exception` |
| POST | `/api/3/vulnerability_exceptions/<id>/{approve\|reject\|reopen\|recall}` | `nexpose-update-vulnerability-exception-status` |
| PUT | `/api/3/vulnerability_exceptions/<id>/expires` | `nexpose-update-vulnerability-exception-expiration` |

### Tags
| GET/POST | `/api/3/tags` | `nexpose-list-tag`, `nexpose-create-tag` |
| GET/PUT/DELETE | `/api/3/tags/<id>` | `nexpose-delete-tag` |
| PUT | `/api/3/tags/<id>/search_criteria` | `nexpose-update-tag-search-criteria` |
| GET/POST/DELETE | `/api/3/tags/<id>/assets` \| `asset_groups` | `nexpose-{list,add,remove}-tag-{asset,asset-group}` |

### Asset Groups
| GET/POST | `/api/3/asset_groups` | `nexpose-list-asset-group`, `nexpose-create-asset-group` |
| GET/PUT/DELETE | `/api/3/asset_groups/<id>` | (CRUD) |

### Reports
| GET | `/api/3/report_templates` | `nexpose-get-report-templates` |
| POST | `/api/3/reports` | `nexpose-create-sites-report`, `nexpose-create-assets-report`, `nexpose-create-scan-report` |
| POST | `/api/3/reports/<id>/generate` | (exécution) |
| GET | `/api/3/reports/<id>/history/<inst>` | `nexpose-get-report-status` |
| GET | `/api/3/reports/<id>/history/<inst>/output` | `nexpose-download-report` (retourne un PDF placeholder) |

## Dataset

- **40 vulnérabilités** réelles (Log4Shell, ProxyLogon, PrintNightmare, Zerologon, MOVEit, Follina, Spring4Shell, EternalBlue, BlueKeep, PAN-OS 2024, regreSSHion, etc.) avec CVSS v2/v3, score PCI, catégories, exploits, malware kits
- **~18 assets** : 6 personas Business Corp (Alice, Bob, Charlie, David, Emma, Flora) + 12 serveurs générés (web, db, mail, AD, VPN, monitoring, CI, cloud)
- **5 sites** : HQ Paris, DR Site, Cloud Ops, Dev Lab, Remote Workers
- **4 scan engines** dont Rapid7 Cloud Engine
- **8 scans historiques** + start/pause/resume/stop stateful
- **Stubs pré-remplis** pour shared credentials, vulnerability exceptions, tags, asset groups, report templates

Les IDs, dates et affectations sont générés avec un seed déterministe : deux exécutions produisent exactement les mêmes réponses.

## Installation locale

```bash
cd simulator
pip install -r requirements.txt
python app.py
# -> http://localhost:8080
```

### Tests rapides

```bash
# Health (sans auth)
curl http://localhost:8080/health

# Liste assets
curl -u nxadmin:nxadmin-secret \
  "http://localhost:8080/api/3/assets?size=5"

# Détail asset
curl -u nxadmin:nxadmin-secret \
  "http://localhost:8080/api/3/assets/100"

# Vulnérabilités sur un asset
curl -u nxadmin:nxadmin-secret \
  "http://localhost:8080/api/3/assets/100/vulnerabilities"

# Recherche assets (DSL Nexpose)
curl -u nxadmin:nxadmin-secret -X POST \
  -H 'Content-Type: application/json' \
  -d '{"match":"all","filters":[{"field":"host-name","operator":"contains","value":"BSNS"}]}' \
  "http://localhost:8080/api/3/assets/search"

# Start / stop scan
curl -u nxadmin:nxadmin-secret -X POST \
  -H 'Content-Type: application/json' \
  -d '{"name":"demo scan"}' \
  "http://localhost:8080/api/3/sites/1/scans"
curl -u nxadmin:nxadmin-secret -X POST \
  "http://localhost:8080/api/3/scans/6000/stop"
```

## Déploiement sur GCP Cloud Run

```bash
bash deploy-cloudrun.sh
```

Personnaliser les credentials :
```bash
NEXPOSE_USERNAME="myuser" NEXPOSE_PASSWORD="mypass" bash deploy-cloudrun.sh
```

## Configuration dans XSIAM

**Settings → Integrations → Rapid7 InsightVM** :

| Paramètre | Valeur |
|---|---|
| Server URL | `https://rapid7-nexpose-simulator-<hash>-ew.a.run.app` |
| Username | `nxadmin` |
| Password | `nxadmin-secret` |
| Token 2FA | *(laisser vide)* |
| Trust any certificate | *(non nécessaire, Cloud Run cert valide)* |

## Structure du projet

```
Rapid7InsightVM-simul/
├── README.md
├── cloudbuild.yaml
├── deploy-cloudrun.sh
├── deployment/
│   ├── Dockerfile
│   └── app.yaml
└── simulator/
    ├── app.py                # Flask app factory + blueprint registration
    ├── auth.py               # HTTP Basic Auth
    ├── config.py             # env vars: creds, pagination, dataset sizes
    ├── requirements.txt
    ├── generators/
    │   ├── base.py           # personas + OS fingerprints + page envelope
    │   ├── vulnerabilities.py # 40 vulnérabilités réelles (Log4Shell, ProxyLogon, ...)
    │   ├── assets.py         # 18 assets (6 personas + 12 serveurs)
    │   ├── sites.py          # 5 sites
    │   ├── scans.py          # 8 scans historiques + ScanStore live
    │   └── catalog.py        # instantiation unique
    └── routes/
        ├── _helpers.py       # pagination
        ├── assets.py         # /api/3/assets + /search + /<id>/vulnerabilities
        ├── vulnerabilities.py# /api/3/vulnerabilities
        ├── sites.py          # /api/3/sites + credentials + schedules + targets
        ├── scans.py          # /api/3/scans + /scan_engines
        ├── shared_credentials.py
        ├── vulnerability_exceptions.py
        ├── tags.py
        ├── asset_groups.py
        └── reports.py        # templates + create + generate + download
```

## Personas partagés — Business Corp

Ces données viennent de [xsiam-shared-personas](https://github.com/JCourtemanche/xsiam-shared-personas) et sont identiques dans tous les simulateurs.

| Utilisateur | Email | Hostname | IP | OS |
|---|---|---|---|---|
| Alice Dupont | alice.dupont@business.org | BSNS-WIN-ALICE | 192.168.1.1 | Windows 10 Pro |
| Bob Martin | bob.martin@business.org | BSNS-MAC-BOB | 192.168.1.2 | macOS 13 Ventura |
| Charlie Durant | charlie.durant@business.org | BSNS-WIN-CHARLIE | 192.168.1.3 | Windows 11 Pro |
| David Lefebvre | david.lefebvre@business.org | BSNS-WIN-DAVID | 192.168.1.4 | Windows 10 Pro |
| Emma Leroy | emma.leroy@business.org | BSNS-MAC-EMMA | 192.168.1.5 | macOS 14 Sonoma |
| Flora Moreau | flora.moreau@business.org | BSNS-MOB-FLORA | 192.168.1.6 | iOS 17 |

## Simulateurs frères

| Projet | API simulée |
|---|---|
| [proofpoint-tap-simulator](https://github.com/JCourtemanche/proofpoint-tap-simulator) | ProofPoint TAP |
| [sentinelone-simul](https://github.com/JCourtemanche/sentinelone-simul) | SentinelOne |
| [cato-networks-simul](https://github.com/JCourtemanche/cato-networks-simul) | Cato Networks |
| [cyberwatch-simul](https://github.com/JCourtemanche/cyberwatch-simul) | Cyberwatch |
| [Rapid7InsightVM-simul](https://github.com/JCourtemanche/Rapid7InsightVM-simul) | Rapid7 Nexpose / InsightVM (on-prem) |
