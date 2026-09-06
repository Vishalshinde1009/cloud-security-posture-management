import hashlib
import logging
from dataclasses import dataclass
from typing import List, Dict, Tuple, Set, Optional

from app.scanner.rules.base import BaseRule, RuleResult
from app.scanner.rules.registry import RuleRegistry, default_registry
from app.scanner.providers.base import DiscoveredResource

logger = logging.getLogger("cspm.rules.executor")


@dataclass
class FindingCandidate:
    """
    Intermediate candidate finding generated when a security rule matches a violation.
    Carries the evaluated rule, target asset, configuration evidence, and unique fingerprint.
    """
    rule: BaseRule
    resource: DiscoveredResource
    result: RuleResult
    finding_identifier: str


class RuleExecutor:
    """
    Orchestrates the evaluation of applicable security detection rules against discovered assets.
    Provides complete error containment so that an exception in one rule never interrupts
    the overall scan or prevents other rules from executing.
    """

    def __init__(self, registry: Optional[RuleRegistry] = None):
        self.registry = registry or default_registry

    def execute_rules(
        self,
        resources: List[DiscoveredResource],
        disabled_rule_ids: Optional[Set[str]] = None,
    ) -> Tuple[List[FindingCandidate], Dict[str, str]]:
        """
        Evaluates applicable enabled rules against discovered cloud assets.
        Returns:
            - List of FindingCandidate instances representing verified violations.
            - Dictionary of any rule execution errors keyed by 'resource_id:rule_id'.
        """
        candidates: List[FindingCandidate] = []
        errors: Dict[str, str] = {}
        disabled = disabled_rule_ids or set()

        logger.info(f"Executing security rules against {len(resources)} discovered cloud assets.")

        for res in resources:
            applicable_rules = self.registry.get_applicable_rules(res)

            for rule in applicable_rules:
                if rule.rule_id in disabled:
                    continue

                try:
                    res_result = rule.evaluate(res)

                    if res_result.matched:
                        # Deterministic finding fingerprint
                        # Based on account, resource_id, and rule_id
                        account_id = res.account_id or "default"
                        fingerprint_raw = f"{account_id}:{res.resource_id}:{rule.rule_id}"
                        fingerprint = hashlib.sha256(fingerprint_raw.encode("utf-8")).hexdigest()

                        candidate = FindingCandidate(
                            rule=rule,
                            resource=res,
                            result=res_result,
                            finding_identifier=fingerprint,
                        )
                        candidates.append(candidate)
                        logger.debug(f"Rule match: {rule.rule_id} on {res.resource_id} (Fingerprint: {fingerprint[:12]}...)")

                except Exception as e:
                    err_key = f"{res.resource_id}:{rule.rule_id}"
                    err_msg = f"Rule execution failed for {rule.rule_id} on {res.resource_id}: {str(e)}"
                    logger.error(err_msg, exc_info=True)
                    errors[err_key] = str(e)

        logger.info(f"Rule execution complete: {len(candidates)} finding candidates identified, {len(errors)} execution errors.")
        return candidates, errors
