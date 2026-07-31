"""
Plan File - Full-fidelity save/load of a MigrationPlan.

The saved migration_plan.json is a complete, executable artifact:
`cli.py --from-plan migration_plan.json --execute` runs the migration from
the file without re-planning. This creates a review-and-edit gate between
planning and execution - delete a policy from the file and it won't be
created; the file is also a diffable per-ACP record of what was migrated.

Format versioning: bump PLAN_FORMAT_VERSION on incompatible changes.
load_plan refuses files with a newer version than it understands.
"""

import json
from dataclasses import asdict
from datetime import datetime
from typing import Dict, Any, Optional

from models import (
    WatchGuardAddress, WatchGuardService, WatchGuardAddressGroup,
    WatchGuardServiceGroup, FMCObject
)
from .planner import MigrationPlan

PLAN_FORMAT_VERSION = 1

# Maps the class tag written at save time back to a constructor.
_WG_CLASSES = {
    'WatchGuardAddress': WatchGuardAddress,
    'WatchGuardService': WatchGuardService,
    'WatchGuardAddressGroup': WatchGuardAddressGroup,
    'WatchGuardServiceGroup': WatchGuardServiceGroup,
}


def _tag_for(obj) -> str:
    cls_name = type(obj).__name__
    if cls_name not in _WG_CLASSES:
        raise TypeError(f"Cannot serialize plan object of type {cls_name}")
    return cls_name


def _fmc_obj_to_dict(obj: FMCObject) -> Dict[str, Any]:
    return asdict(obj)


def _fmc_obj_from_dict(d: Dict[str, Any]) -> FMCObject:
    return FMCObject(**d)


def save_plan(plan: MigrationPlan, filename: str,
              metadata: Optional[Dict[str, Any]] = None,
              extra_reports: Optional[Dict[str, Any]] = None):
    """Serialize a MigrationPlan to JSON with full fidelity."""
    data = {
        'format_version': PLAN_FORMAT_VERSION,
        'metadata': {
            'created': datetime.now().isoformat(),
            **(metadata or {})
        },
        'statistics': plan.statistics,
        'address_mappings': {
            name: _fmc_obj_to_dict(obj) for name, obj in plan.address_mappings.items()
        },
        'service_mappings': {
            name: _fmc_obj_to_dict(obj) for name, obj in plan.service_mappings.items()
        },
        'application_mappings': {
            name: _fmc_obj_to_dict(obj) for name, obj in plan.application_mappings.items()
        },
        'objects_to_create': [
            {
                'type': entry['type'],
                'wg_class': _tag_for(entry['wg_object']),
                'wg_object': asdict(entry['wg_object'])
            }
            for entry in plan.objects_to_create
        ],
        'service_groups_to_create': [
            asdict(group) for group in plan.service_groups_to_create
        ],
        'policies_to_create': plan.policies_to_create,
        'skipped_policies': plan.skipped_policies,
        'warnings': plan.warnings,
        'errors': plan.errors,
    }

    # Zone/user/application mapping reports etc. - informational only,
    # ignored by load_plan.
    if extra_reports:
        data['reports'] = extra_reports

    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)


def load_plan(filename: str) -> MigrationPlan:
    """Reconstruct a MigrationPlan from a saved plan file."""
    with open(filename, 'r') as f:
        data = json.load(f)

    version = data.get('format_version')
    if version is None:
        raise ValueError(
            f"{filename} is not an executable plan file (no format_version). "
            "It was probably written by an older version of this tool - "
            "re-run the planning step to regenerate it."
        )
    if version > PLAN_FORMAT_VERSION:
        raise ValueError(
            f"{filename} has plan format v{version}; this tool understands "
            f"up to v{PLAN_FORMAT_VERSION}. Update the tool."
        )

    objects_to_create = []
    for entry in data.get('objects_to_create', []):
        cls = _WG_CLASSES.get(entry.get('wg_class'))
        if cls is None:
            raise ValueError(f"Unknown wg_class in plan: {entry.get('wg_class')}")
        objects_to_create.append({
            'type': entry['type'],
            'wg_object': cls(**entry['wg_object'])
        })

    return MigrationPlan(
        address_mappings={
            name: _fmc_obj_from_dict(d)
            for name, d in data.get('address_mappings', {}).items()
        },
        service_mappings={
            name: _fmc_obj_from_dict(d)
            for name, d in data.get('service_mappings', {}).items()
        },
        application_mappings={
            name: _fmc_obj_from_dict(d)
            for name, d in data.get('application_mappings', {}).items()
        },
        objects_to_create=objects_to_create,
        policies_to_create=data.get('policies_to_create', []),
        statistics=data.get('statistics', {}),
        service_groups_to_create=[
            WatchGuardServiceGroup(**g)
            for g in data.get('service_groups_to_create', [])
        ],
        skipped_policies=data.get('skipped_policies', []),
    )
