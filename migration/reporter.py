"""
Migration Reporter - Unified reporting for WatchGuard to FMC migration.

Collects all errors, warnings, and statistics during migration and
generates a comprehensive migration_report.json file.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ObjectFailure:
    """Record of a failed object creation."""
    type: str
    name: str
    reason: str
    original_data: Optional[Dict] = None


@dataclass
class RuleFailure:
    """Record of a failed rule creation."""
    rule: str
    reason: str
    original_payload: Optional[Dict] = None
    resolved_payload: Optional[Dict] = None


@dataclass
class GroupFailure:
    """Record of a failed group creation."""
    name: str
    reason: str
    original_members: List[str] = field(default_factory=list)


@dataclass
class UnmappedApplication:
    """Record of an unmapped application."""
    rule: str
    application: str
    app_action: str
    reason: str = "No FMC match found"


@dataclass
class UnresolvedObject:
    """Record of an unresolved object in a rule."""
    rule: str
    object: str
    field: str  # source, destination, or service
    reason: str = "Not found in FMC"


@dataclass
class IncompleteRule:
    """Record of a rule created with missing elements."""
    rule: str
    missing: List[str] = field(default_factory=list)
    created: bool = True


class MigrationReporter:
    """
    Collects and reports all migration issues.
    
    Usage:
        reporter = MigrationReporter()
        
        # During object creation
        reporter.object_created("host", "MyHost")
        reporter.object_skipped("host", "ExistingHost", "Already exists")
        reporter.object_failed("service", "PPTP", "Name conflicts with predefined")
        
        # During rule creation
        reporter.rule_created("Allow-HTTP")
        reporter.rule_failed("Block-All", "Invalid action", original, resolved)
        reporter.rule_warning_unresolved("MyRule", "BadObject", "destination")
        reporter.rule_warning_unmapped_app("MyRule", "CustomApp", "Allow-Apps")
        
        # At end
        reporter.save_report()  # Prints absolute path and creates migration_report.json
    """
    
    def __init__(self):
        self.start_time = datetime.now()
        
        # Counters by type
        self._objects_created: Dict[str, int] = {}
        self._objects_skipped: Dict[str, int] = {}
        self._objects_failed: Dict[str, int] = {}
        self._rules_created = 0
        self._rules_failed = 0
        self._rules_with_warnings = 0
        self._groups_created = 0
        self._groups_failed = 0
        self._auto_groups_created = 0
        
        # Detailed records
        self._object_failures: List[ObjectFailure] = []
        self._rule_failures: List[RuleFailure] = []
        self._group_failures: List[GroupFailure] = []
        self._unmapped_applications: List[UnmappedApplication] = []
        self._unresolved_objects: List[UnresolvedObject] = []
        self._incomplete_rules: List[IncompleteRule] = []
        
        # Track rules with warnings to avoid double-counting
        self._warned_rules: set = set()
    
    # ========== Object tracking ==========
    
    def object_created(self, obj_type: str, name: str):
        """Record successful object creation."""
        self._objects_created[obj_type] = self._objects_created.get(obj_type, 0) + 1
    
    def object_skipped(self, obj_type: str, name: str, reason: str = "Already exists"):
        """Record skipped object (e.g., already exists in FMC)."""
        self._objects_skipped[obj_type] = self._objects_skipped.get(obj_type, 0) + 1
    
    def object_failed(self, obj_type: str, name: str, reason: str, 
                      original_data: Optional[Dict] = None):
        """Record failed object creation."""
        self._objects_failed[obj_type] = self._objects_failed.get(obj_type, 0) + 1
        self._object_failures.append(ObjectFailure(
            type=obj_type,
            name=name,
            reason=reason,
            original_data=original_data
        ))
    
    # ========== Group tracking ==========
    
    def group_created(self, name: str):
        """Record successful group creation."""
        self._groups_created += 1
    
    def group_failed(self, name: str, reason: str, original_members: List[str] = None):
        """Record failed group creation."""
        self._groups_failed += 1
        self._group_failures.append(GroupFailure(
            name=name,
            reason=reason,
            original_members=original_members or []
        ))
    
    def auto_group_created(self, rule_name: str, group_name: str, member_count: int):
        """Record auto-created group for >200 object rules."""
        self._auto_groups_created += 1
        self._groups_created += 1
    
    # ========== Rule tracking ==========
    
    def rule_created(self, rule_name: str, has_warnings: bool = False):
        """Record successful rule creation."""
        self._rules_created += 1
        if has_warnings and rule_name not in self._warned_rules:
            self._rules_with_warnings += 1
            self._warned_rules.add(rule_name)
    
    def rule_failed(self, rule_name: str, reason: str,
                    original_payload: Optional[Dict] = None,
                    resolved_payload: Optional[Dict] = None):
        """Record failed rule creation."""
        self._rules_failed += 1
        self._rule_failures.append(RuleFailure(
            rule=rule_name,
            reason=reason,
            original_payload=original_payload,
            resolved_payload=resolved_payload
        ))
    
    def rule_warning_unmapped_app(self, rule_name: str, application: str, 
                                   app_action: str):
        """Record warning for unmapped application in rule."""
        self._unmapped_applications.append(UnmappedApplication(
            rule=rule_name,
            application=application,
            app_action=app_action
        ))
        if rule_name not in self._warned_rules:
            self._rules_with_warnings += 1
            self._warned_rules.add(rule_name)
    
    def rule_warning_unresolved(self, rule_name: str, object_name: str, 
                                 field: str, reason: str = "Not found in FMC"):
        """Record warning for unresolved object in rule."""
        self._unresolved_objects.append(UnresolvedObject(
            rule=rule_name,
            object=object_name,
            field=field,
            reason=reason
        ))
        if rule_name not in self._warned_rules:
            self._rules_with_warnings += 1
            self._warned_rules.add(rule_name)
    
    def rule_incomplete(self, rule_name: str, missing: List[str], created: bool = True):
        """Record that a rule was created but is incomplete."""
        self._incomplete_rules.append(IncompleteRule(
            rule=rule_name,
            missing=missing,
            created=created
        ))
        if rule_name not in self._warned_rules:
            self._rules_with_warnings += 1
            self._warned_rules.add(rule_name)
    
    # ========== Report generation ==========
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        total_objects_created = sum(self._objects_created.values())
        total_objects_skipped = sum(self._objects_skipped.values())
        total_objects_failed = sum(self._objects_failed.values())
        
        return {
            "migration_started": self.start_time.isoformat(),
            "migration_completed": datetime.now().isoformat(),
            "duration_seconds": round((datetime.now() - self.start_time).total_seconds(), 2),
            "total_rules": self._rules_created + self._rules_failed,
            "rules_created": self._rules_created,
            "rules_with_warnings": self._rules_with_warnings,
            "rules_failed": self._rules_failed,
            "objects_created": total_objects_created,
            "objects_skipped": total_objects_skipped,
            "objects_failed": total_objects_failed,
            "groups_created": self._groups_created,
            "groups_failed": self._groups_failed,
            "auto_groups_created": self._auto_groups_created,
            "objects_created_by_type": dict(self._objects_created),
            "objects_skipped_by_type": dict(self._objects_skipped),
            "objects_failed_by_type": dict(self._objects_failed)
        }
    
    def get_errors(self) -> Dict[str, List[Dict]]:
        """Get all errors."""
        return {
            "object_creation_failures": [
                {"type": f.type, "name": f.name, "reason": f.reason}
                for f in self._object_failures
            ],
            "rule_creation_failures": [
                {"rule": f.rule, "reason": f.reason}
                for f in self._rule_failures
            ],
            "group_creation_failures": [
                {"name": f.name, "reason": f.reason, "original_members": f.original_members}
                for f in self._group_failures
            ]
        }
    
    def get_warnings(self) -> Dict[str, List[Dict]]:
        """Get all warnings."""
        return {
            "unmapped_applications": [
                {"rule": w.rule, "application": w.application, 
                 "app_action": w.app_action, "reason": w.reason}
                for w in self._unmapped_applications
            ],
            "unresolved_objects": [
                {"rule": w.rule, "object": w.object, 
                 "field": w.field, "reason": w.reason}
                for w in self._unresolved_objects
            ],
            "incomplete_rules": [
                {"rule": w.rule, "missing": w.missing, "created": w.created}
                for w in self._incomplete_rules
            ]
        }
    
    def get_detailed_failures(self) -> Dict[str, List[Dict]]:
        """Get detailed failure records including payloads for debugging."""
        return {
            "rule_failures": [
                {
                    "rule": f.rule,
                    "reason": f.reason,
                    "original_payload": f.original_payload,
                    "resolved_payload": f.resolved_payload
                }
                for f in self._rule_failures
            ],
            "object_failures": [
                {
                    "type": f.type,
                    "name": f.name,
                    "reason": f.reason,
                    "original_data": f.original_data
                }
                for f in self._object_failures
                if f.original_data  # Only include those with data
            ]
        }
    
    def build_report(self) -> Dict[str, Any]:
        """Build the complete migration report."""
        return {
            "summary": self.get_summary(),
            "errors": self.get_errors(),
            "warnings": self.get_warnings(),
            "detailed_failures": self.get_detailed_failures()
        }
    
    def save_report(self, directory: str = ".") -> str:
        """
        Save the migration report to migration_report.json.
        
        Returns the absolute path to the report file.
        """
        report = self.build_report()
        
        filepath = os.path.join(directory, "migration_report.json")
        abs_path = os.path.abspath(filepath)
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Print summary to console
        print("\n" + "=" * 60)
        print("MIGRATION REPORT")
        print("=" * 60)
        
        summary = report["summary"]
        print(f"\n📊 Summary:")
        print(f"   Duration: {summary['duration_seconds']} seconds")
        print(f"   Rules: {summary['rules_created']}/{summary['total_rules']} created", end="")
        if summary['rules_with_warnings'] > 0:
            print(f" ({summary['rules_with_warnings']} with warnings)", end="")
        if summary['rules_failed'] > 0:
            print(f" ({summary['rules_failed']} failed)", end="")
        print()
        
        print(f"   Objects: {summary['objects_created']} created, "
              f"{summary['objects_skipped']} skipped, {summary['objects_failed']} failed")
        
        if summary['groups_created'] > 0 or summary['groups_failed'] > 0:
            print(f"   Groups: {summary['groups_created']} created", end="")
            if summary['auto_groups_created'] > 0:
                print(f" ({summary['auto_groups_created']} auto-generated)", end="")
            if summary['groups_failed'] > 0:
                print(f", {summary['groups_failed']} failed", end="")
            print()
        
        errors = report["errors"]
        warnings = report["warnings"]
        
        total_errors = (len(errors["object_creation_failures"]) + 
                       len(errors["rule_creation_failures"]) + 
                       len(errors["group_creation_failures"]))
        
        total_warnings = (len(warnings["unmapped_applications"]) + 
                         len(warnings["unresolved_objects"]) + 
                         len(warnings["incomplete_rules"]))
        
        if total_errors > 0:
            print(f"\n❌ Errors: {total_errors}")
            if errors["object_creation_failures"]:
                print(f"   - Object creation failures: {len(errors['object_creation_failures'])}")
            if errors["rule_creation_failures"]:
                print(f"   - Rule creation failures: {len(errors['rule_creation_failures'])}")
            if errors["group_creation_failures"]:
                print(f"   - Group creation failures: {len(errors['group_creation_failures'])}")
        
        if total_warnings > 0:
            print(f"\n⚠️  Warnings: {total_warnings}")
            if warnings["unmapped_applications"]:
                print(f"   - Unmapped applications: {len(warnings['unmapped_applications'])}")
            if warnings["unresolved_objects"]:
                print(f"   - Unresolved objects: {len(warnings['unresolved_objects'])}")
            if warnings["incomplete_rules"]:
                print(f"   - Incomplete rules: {len(warnings['incomplete_rules'])}")
        
        print(f"\n📄 Full report saved to: {abs_path}")
        
        return abs_path
