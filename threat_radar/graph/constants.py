"""Constants for graph analysis and attack path discovery."""

from typing import Final

# CVSS Threat Level Thresholds
CVSS_CRITICAL_THRESHOLD: Final[float] = 9.0
CVSS_HIGH_THRESHOLD: Final[float] = 7.0
CVSS_MEDIUM_THRESHOLD: Final[float] = 4.0

# Path Analysis Limits (DoS Prevention)
MAX_ATTACK_PATHS: Final[int] = 1000
MAX_PATH_LENGTH: Final[int] = 20
MAX_PRIVILEGE_ESCALATIONS: Final[int] = 500
MAX_LATERAL_MOVEMENTS: Final[int] = 1000
MAX_GRAPH_TRAVERSAL_DEPTH: Final[int] = 50
MAX_NODES_TO_VISIT: Final[int] = 10000

# Exploitability Scoring
EXPLOITABILITY_STEP_PENALTY: Final[float] = 0.1
MIN_EXPLOITABILITY: Final[float] = 0.0
MAX_EXPLOITABILITY: Final[float] = 1.0

# Difficulty Rating Thresholds
ESCALATION_EASY_MAX_STEPS: Final[int] = 3
ESCALATION_MEDIUM_MAX_STEPS: Final[int] = 6

LATERAL_MOVEMENT_EASY_MAX_STEPS: Final[int] = 3
LATERAL_MOVEMENT_MEDIUM_MAX_STEPS: Final[int] = 5

# Risk Scoring Weights
RISK_WEIGHT_CRITICAL: Final[int] = 10
RISK_WEIGHT_HIGH: Final[int] = 5
RISK_WEIGHT_PRIVILEGE_ESCALATION: Final[int] = 3
RISK_WEIGHT_LATERAL_MOVEMENT: Final[int] = 1

# Business Context Risk Multipliers
BUSINESS_CRITICAL_MULTIPLIER: Final[float] = 1.5
BUSINESS_HIGH_MULTIPLIER: Final[float] = 1.3
PCI_SCOPE_MULTIPLIER: Final[float] = 1.4
HIPAA_SCOPE_MULTIPLIER: Final[float] = 1.3
CUSTOMER_FACING_MULTIPLIER: Final[float] = 1.2

# Timeout Settings (seconds)
GRAPH_ANALYSIS_TIMEOUT: Final[int] = 300  # 5 minutes
PATH_DISCOVERY_TIMEOUT: Final[int] = 120  # 2 minutes

# Validation Limits
MAX_CRITICALITY_SCORE: Final[int] = 100
MIN_CRITICALITY_SCORE: Final[int] = 0
