"""
Security scoring engine for NetSentinel.

This module calculates security scores based on findings from
static analysis and network probes. It implements:
- Weighted scoring algorithms
- Severity categorization (Critical, High, Medium, Low, Info)
- Compliance mapping (OWASP Top 10 2021)
- CVSS 3.1 base score calculation

All functions in this module are PURE - deterministic with no side effects.
The scoring system provides actionable metrics for security posture.
"""

from typing import Dict, List, Optional
import math

from netsentinel.models import Finding
from netsentinel.config import (
    SEVERITY_PENALTIES,
    DOMAIN_WEIGHTS,
    GRADE_THRESHOLDS,
    OWASP_MAPPING,
)


# =============================================================================
# CVSS 3.1 CONSTANTS
# =============================================================================

# Attack Vector (AV) values
AV_VALUES = {
    'N': 0.85,   # Network
    'A': 0.62,   # Adjacent
    'L': 0.55,   # Local
    'P': 0.20,   # Physical
}

# Attack Complexity (AC) values
AC_VALUES = {
    'L': 0.77,   # Low
    'H': 0.44,   # High
}

# Privileges Required (PR) values - depends on Scope
PR_VALUES_UNCHANGED = {
    'N': 0.85,   # None
    'L': 0.62,   # Low
    'H': 0.27,   # High
}

PR_VALUES_CHANGED = {
    'N': 0.85,   # None
    'L': 0.68,   # Low
    'H': 0.50,   # High
}

# User Interaction (UI) values
UI_VALUES = {
    'N': 0.85,   # None
    'R': 0.62,   # Required
}

# Impact values (C, I, A)
IMPACT_VALUES = {
    'N': 0.00,   # None
    'L': 0.22,   # Low
    'H': 0.56,   # High
}

# Human-readable labels for CVSS components
CVSS_LABELS = {
    'AV': {'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical'},
    'AC': {'L': 'Low', 'H': 'High'},
    'PR': {'N': 'None', 'L': 'Low', 'H': 'High'},
    'UI': {'N': 'None', 'R': 'Required'},
    'S': {'U': 'Unchanged', 'C': 'Changed'},
    'C': {'N': 'None', 'L': 'Low', 'H': 'High'},
    'I': {'N': 'None', 'L': 'Low', 'H': 'High'},
    'A': {'N': 'None', 'L': 'Low', 'H': 'High'},
}


# =============================================================================
# DOMAIN SCORING FUNCTIONS
# =============================================================================

def compute_domain_score(findings: List[Finding]) -> int:
    """
    Compute score for a single domain.
    
    Formula: score = max(0, 100 - sum(penalty for each finding))
    
    Penalties by severity:
    - critical: 25 points
    - high: 15 points
    - medium: 8 points
    - low: 3 points
    - info: 0 points
    
    Multiple findings of same type are each penalized independently.
    Floor at 0 - score cannot go negative.
    
    Args:
        findings: List of Finding objects for a single domain
        
    Returns:
        Domain score as integer (0-100)
    """
    total_penalty = 0
    
    for finding in findings:
        penalty = SEVERITY_PENALTIES.get(finding.severity, 0)
        total_penalty += penalty
    
    return max(0, 100 - total_penalty)


def compute_overall_score(domain_scores: Dict[str, int]) -> float:
    """
    Compute weighted overall score from domain scores.
    
    Formula: weighted = (network × 0.25) + (tls × 0.30) + (http × 0.25) + (dns × 0.20)
    
    Args:
        domain_scores: Dict mapping domain name to score (0-100)
        
    Returns:
        Weighted overall score as float (0.0-100.0)
    """
    weighted = 0.0
    
    for domain, weight in DOMAIN_WEIGHTS.items():
        # Default to 100 if no findings (perfect score when untested)
        score = domain_scores.get(domain, 100)
        weighted += score * weight
    
    return weighted


def compute_grade(score: float) -> str:
    """
    Convert numeric score to letter grade.
    
    Thresholds:
    - A: 90-100
    - B: 75-89
    - C: 60-74
    - D: 45-59
    - F: 0-44
    
    Args:
        score: Numeric score (0.0-100.0)
        
    Returns:
        Letter grade as string ('A', 'B', 'C', 'D', or 'F')
    """
    # Process thresholds in descending order
    for grade in ['A', 'B', 'C', 'D']:
        if score >= GRADE_THRESHOLDS[grade]:
            return grade
    return 'F'


# =============================================================================
# OWASP COVERAGE FUNCTIONS
# =============================================================================

def compute_owasp_coverage(findings: List[Finding]) -> List[Dict]:
    """
    Compute OWASP Top 10 2021 coverage from findings.
    
    Each OWASP category gets:
    - status: 'pass' (no findings), 'fail' (has findings), 'untested' (not implemented)
    - finding_count: number of findings in this category
    
    Args:
        findings: List of all Finding objects
        
    Returns:
        List of dicts with owasp_id, category, status, and finding_count
    """
    coverage = []
    
    # Group findings by OWASP ID
    owasp_findings: Dict[str, List[Finding]] = {}
    for f in findings:
        owasp_id = f.owasp_id
        if owasp_id:
            if owasp_id not in owasp_findings:
                owasp_findings[owasp_id] = []
            owasp_findings[owasp_id].append(f)
    
    # Check each OWASP category
    for owasp_id, category_name in OWASP_MAPPING.items():
        finding_count = len(owasp_findings.get(owasp_id, []))
        
        if finding_count > 0:
            status = 'fail'
        else:
            # No findings = pass (assumes category was tested)
            # For explicit untested tracking, callers would need to pass metadata
            status = 'pass'
        
        coverage.append({
            'owasp_id': owasp_id,
            'category': category_name,
            'status': status,
            'finding_count': finding_count,
        })
    
    return coverage


# =============================================================================
# SUMMARY STATISTICS FUNCTIONS
# =============================================================================

def compute_summary(findings: List[Finding]) -> Dict:
    """
    Compute summary statistics for findings.
    
    Args:
        findings: List of all Finding objects
        
    Returns:
        Dict with total_findings, by_severity counts, highest_cvss, and
        highest_cvss_finding title
    """
    by_severity = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0,
    }
    
    highest_cvss = 0.0
    highest_cvss_finding = ''
    
    for finding in findings:
        # Count by severity
        severity = finding.severity
        if severity in by_severity:
            by_severity[severity] += 1
        
        # Track highest CVSS
        if finding.cvss_score > highest_cvss:
            highest_cvss = finding.cvss_score
            highest_cvss_finding = finding.title
    
    return {
        'total_findings': len(findings),
        'by_severity': by_severity,
        'highest_cvss': highest_cvss,
        'highest_cvss_finding': highest_cvss_finding,
    }


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def generate_score_report(findings: List[Finding]) -> Dict:
    """
    Generate complete score report from findings.
    
    This is the main entry point. It calls all other scoring functions
    and assembles the complete score object.
    
    Args:
        findings: List of Finding objects from all modules
        
    Returns:
        Complete score report dict with scores, owasp_coverage, and summary
    """
    # 1. Compute per-domain scores
    domain_scores = {}
    for domain in ['network', 'tls', 'http', 'dns', 'static']:
        domain_findings = [f for f in findings if f.domain == domain]
        domain_scores[domain] = compute_domain_score(domain_findings)
    
    # 2. Compute weighted overall score
    weighted_overall = compute_overall_score(domain_scores)
    
    # 3. Determine letter grade
    grade = compute_grade(weighted_overall)
    
    # 4. Compute OWASP coverage
    owasp_coverage = compute_owasp_coverage(findings)
    
    # 5. Compute summary statistics
    summary = compute_summary(findings)
    
    return {
        'scores': {
            'network': domain_scores.get('network', 100),
            'tls': domain_scores.get('tls', 100),
            'http': domain_scores.get('http', 100),
            'dns': domain_scores.get('dns', 100),
            'static': domain_scores.get('static', 100),
            'weighted_overall': round(weighted_overall, 2),
            'grade': grade,
        },
        'owasp_coverage': owasp_coverage,
        'summary': summary,
    }


# =============================================================================
# CVSS 3.1 CALCULATION FUNCTIONS
# =============================================================================

def parse_cvss_vector(vector: str) -> Dict[str, str]:
    """
    Parse CVSS 3.1 vector string into components.
    
    Args:
        vector: CVSS vector string (e.g., 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N')
        
    Returns:
        Dict mapping component abbreviations to values
    """
    components: Dict[str, str] = {}
    
    # Remove prefix if present
    if vector.startswith('CVSS:3.1/'):
        vector = vector[9:]
    elif vector.startswith('CVSS:3.0/'):
        vector = vector[9:]
    
    for part in vector.split('/'):
        if ':' in part:
            key, value = part.split(':', 1)
            components[key] = value
    
    return components


def calculate_cvss_base_score(vector: str) -> float:
    """
    Calculate CVSS 3.1 base score from vector string.
    
    Implements the full CVSS 3.1 base score formula per FIRST specification.
    
    Args:
        vector: CVSS 3.1 vector string
            Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
            
    Returns:
        Base score as float (0.0-10.0)
    """
    components = parse_cvss_vector(vector)
    
    # Get component values with defaults
    av = components.get('AV', 'N')
    ac = components.get('AC', 'L')
    pr = components.get('PR', 'N')
    ui = components.get('UI', 'N')
    s = components.get('S', 'U')
    c = components.get('C', 'N')
    i = components.get('I', 'N')
    a = components.get('A', 'N')
    
    # Determine if scope is changed
    scope_changed = (s == 'C')
    
    # Get numeric values for components
    av_val = AV_VALUES.get(av, 0.85)
    ac_val = AC_VALUES.get(ac, 0.77)
    ui_val = UI_VALUES.get(ui, 0.85)
    
    # Privileges required depends on scope
    if scope_changed:
        pr_val = PR_VALUES_CHANGED.get(pr, 0.85)
    else:
        pr_val = PR_VALUES_UNCHANGED.get(pr, 0.85)
    
    # Impact values
    c_val = IMPACT_VALUES.get(c, 0.0)
    i_val = IMPACT_VALUES.get(i, 0.0)
    a_val = IMPACT_VALUES.get(a, 0.0)
    
    # Calculate Impact Sub-Score (ISS)
    iss = 1 - ((1 - c_val) * (1 - i_val) * (1 - a_val))
    
    # Calculate Impact
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
    else:
        impact = 6.42 * iss
    
    # Calculate Exploitability
    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val
    
    # Calculate Base Score
    if impact <= 0:
        base_score = 0.0
    else:
        if scope_changed:
            base_score = min(1.08 * (impact + exploitability), 10.0)
        else:
            base_score = min(impact + exploitability, 10.0)
        
        # Round up to one decimal place
        base_score = math.ceil(base_score * 10) / 10
    
    return base_score


def generate_cvss_vector(
    attack_vector: str = 'N',
    attack_complexity: str = 'L',
    privileges_required: str = 'N',
    user_interaction: str = 'N',
    scope: str = 'U',
    confidentiality: str = 'N',
    integrity: str = 'N',
    availability: str = 'N',
) -> str:
    """
    Generate CVSS 3.1 vector string from components.
    
    Args:
        attack_vector: 'N' (Network), 'A' (Adjacent), 'L' (Local), 'P' (Physical)
        attack_complexity: 'L' (Low), 'H' (High)
        privileges_required: 'N' (None), 'L' (Low), 'H' (High)
        user_interaction: 'N' (None), 'R' (Required)
        scope: 'U' (Unchanged), 'C' (Changed)
        confidentiality: 'N' (None), 'L' (Low), 'H' (High)
        integrity: 'N' (None), 'L' (Low), 'H' (High)
        availability: 'N' (None), 'L' (Low), 'H' (High)
        
    Returns:
        CVSS 3.1 vector string
    """
    return (
        f'CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/'
        f'PR:{privileges_required}/UI:{user_interaction}/S:{scope}/'
        f'C:{confidentiality}/I:{integrity}/A:{availability}'
    )


def get_cvss_breakdown(vector: str) -> Dict[str, str]:
    """
    Convert CVSS vector to human-readable breakdown.
    
    Args:
        vector: CVSS 3.1 vector string
        
    Returns:
        Dict with human-readable labels for each component
    """
    components = parse_cvss_vector(vector)
    
    return {
        'attack_vector': CVSS_LABELS['AV'].get(components.get('AV', 'N'), 'Unknown'),
        'attack_complexity': CVSS_LABELS['AC'].get(components.get('AC', 'L'), 'Unknown'),
        'privileges_required': CVSS_LABELS['PR'].get(components.get('PR', 'N'), 'Unknown'),
        'user_interaction': CVSS_LABELS['UI'].get(components.get('UI', 'N'), 'Unknown'),
        'scope': CVSS_LABELS['S'].get(components.get('S', 'U'), 'Unknown'),
        'confidentiality': CVSS_LABELS['C'].get(components.get('C', 'N'), 'Unknown'),
        'integrity': CVSS_LABELS['I'].get(components.get('I', 'N'), 'Unknown'),
        'availability': CVSS_LABELS['A'].get(components.get('A', 'N'), 'Unknown'),
    }


def get_severity_from_cvss(cvss_score: float) -> str:
    """
    Get severity rating from CVSS score.
    
    CVSS 3.1 severity ratings:
    - None: 0.0
    - Low: 0.1 - 3.9
    - Medium: 4.0 - 6.9
    - High: 7.0 - 8.9
    - Critical: 9.0 - 10.0
    
    Args:
        cvss_score: CVSS base score (0.0-10.0)
        
    Returns:
        Severity string ('critical', 'high', 'medium', 'low', 'info')
    """
    if cvss_score >= 9.0:
        return 'critical'
    elif cvss_score >= 7.0:
        return 'high'
    elif cvss_score >= 4.0:
        return 'medium'
    elif cvss_score >= 0.1:
        return 'low'
    else:
        return 'info'


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_findings_by_domain(findings: List[Finding], domain: str) -> List[Finding]:
    """
    Filter findings by domain.
    
    Args:
        findings: List of all Finding objects
        domain: Domain to filter by ('network', 'tls', 'http', 'dns', 'static')
        
    Returns:
        List of findings matching the specified domain
    """
    return [f for f in findings if f.domain == domain]


def get_findings_by_severity(findings: List[Finding], severity: str) -> List[Finding]:
    """
    Filter findings by severity.
    
    Args:
        findings: List of all Finding objects
        severity: Severity to filter by ('critical', 'high', 'medium', 'low', 'info')
        
    Returns:
        List of findings matching the specified severity
    """
    return [f for f in findings if f.severity == severity]


def get_findings_by_owasp(findings: List[Finding], owasp_id: str) -> List[Finding]:
    """
    Filter findings by OWASP category.
    
    Args:
        findings: List of all Finding objects
        owasp_id: OWASP ID to filter by ('A01' through 'A10')
        
    Returns:
        List of findings matching the specified OWASP category
    """
    return [f for f in findings if f.owasp_id == owasp_id]


def sort_findings_by_cvss(findings: List[Finding], descending: bool = True) -> List[Finding]:
    """
    Sort findings by CVSS score.
    
    Args:
        findings: List of Finding objects
        descending: If True, sort highest to lowest (default True)
        
    Returns:
        New list of findings sorted by CVSS score
    """
    return sorted(findings, key=lambda f: f.cvss_score, reverse=descending)
