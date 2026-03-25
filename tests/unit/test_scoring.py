"""
Unit tests for the scoring engine.

Tests cover:
- Domain score calculation
- Overall weighted score calculation
- Letter grade assignment
- OWASP coverage computation
- Summary statistics
- CVSS calculation and parsing
- Determinism verification
"""

import pytest
from netsentinel.scoring import (
    compute_domain_score,
    compute_overall_score,
    compute_grade,
    compute_owasp_coverage,
    compute_summary,
    generate_score_report,
    parse_cvss_vector,
    calculate_cvss_base_score,
    generate_cvss_vector,
    get_cvss_breakdown,
    get_severity_from_cvss,
    get_findings_by_domain,
    get_findings_by_severity,
    get_findings_by_owasp,
    sort_findings_by_cvss,
)
from netsentinel.models import Finding


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def sample_findings():
    """Create a set of sample findings for testing."""
    return [
        Finding(
            id="f1",
            domain="network",
            title="Open port 23 (Telnet) detected",
            severity="critical",
            cvss_score=9.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            owasp_id="A07",
        ),
        Finding(
            id="f2",
            domain="network",
            title="Open port 21 (FTP) detected",
            severity="high",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            owasp_id="A07",
        ),
        Finding(
            id="f3",
            domain="tls",
            title="TLS 1.0 supported",
            severity="high",
            cvss_score=7.4,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            owasp_id="A02",
        ),
        Finding(
            id="f4",
            domain="tls",
            title="Certificate expires in 25 days",
            severity="high",
            cvss_score=5.9,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
            owasp_id="A02",
        ),
        Finding(
            id="f5",
            domain="http",
            title="Missing Content-Security-Policy header",
            severity="medium",
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            owasp_id="A05",
        ),
        Finding(
            id="f6",
            domain="http",
            title="CORS allows arbitrary origins",
            severity="high",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            owasp_id="A01",
        ),
        Finding(
            id="f7",
            domain="dns",
            title="SPF record uses ~all instead of -all",
            severity="low",
            cvss_score=3.7,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            owasp_id="A05",
        ),
        Finding(
            id="f8",
            domain="http",
            title="Server header reveals version info",
            severity="low",
            cvss_score=2.6,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            owasp_id="A05",
        ),
        Finding(
            id="f9",
            domain="static",
            title="Hardcoded API key found",
            severity="critical",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            owasp_id="A08",
        ),
    ]


@pytest.fixture
def empty_findings():
    """Return empty findings list."""
    return []


# =============================================================================
# DOMAIN SCORE TESTS
# =============================================================================

class TestComputeDomainScore:
    """Tests for compute_domain_score function."""

    def test_empty_findings_returns_100(self, empty_findings):
        """No findings should result in perfect score."""
        score = compute_domain_score(empty_findings)
        assert score == 100

    def test_single_critical_finding(self):
        """Single critical finding should deduct 25 points."""
        findings = [
            Finding(domain="network", severity="critical", title="Test")
        ]
        score = compute_domain_score(findings)
        assert score == 75

    def test_single_high_finding(self):
        """Single high finding should deduct 15 points."""
        findings = [
            Finding(domain="network", severity="high", title="Test")
        ]
        score = compute_domain_score(findings)
        assert score == 85

    def test_single_medium_finding(self):
        """Single medium finding should deduct 8 points."""
        findings = [
            Finding(domain="network", severity="medium", title="Test")
        ]
        score = compute_domain_score(findings)
        assert score == 92

    def test_single_low_finding(self):
        """Single low finding should deduct 3 points."""
        findings = [
            Finding(domain="network", severity="low", title="Test")
        ]
        score = compute_domain_score(findings)
        assert score == 97

    def test_info_finding_no_penalty(self):
        """Info findings should not deduct any points."""
        findings = [
            Finding(domain="network", severity="info", title="Test")
        ]
        score = compute_domain_score(findings)
        assert score == 100

    def test_multiple_findings_cumulative_penalty(self):
        """Multiple findings should apply cumulative penalties."""
        findings = [
            Finding(domain="network", severity="critical", title="Test1"),  # -25
            Finding(domain="network", severity="high", title="Test2"),       # -15
            Finding(domain="network", severity="medium", title="Test3"),     # -8
        ]
        score = compute_domain_score(findings)
        assert score == 52  # 100 - 25 - 15 - 8

    def test_score_floors_at_zero(self):
        """Score should not go below zero."""
        findings = [
            Finding(domain="network", severity="critical", title="Test1"),  # -25
            Finding(domain="network", severity="critical", title="Test2"),  # -25
            Finding(domain="network", severity="critical", title="Test3"),  # -25
            Finding(domain="network", severity="critical", title="Test4"),  # -25
            Finding(domain="network", severity="critical", title="Test5"),  # -25
        ]
        score = compute_domain_score(findings)
        assert score == 0

    def test_unknown_severity_no_penalty(self):
        """Unknown severity should not apply penalty."""
        findings = [
            Finding(domain="network", severity="unknown", title="Test")
        ]
        score = compute_domain_score(findings)
        assert score == 100


# =============================================================================
# OVERALL SCORE TESTS
# =============================================================================

class TestComputeOverallScore:
    """Tests for compute_overall_score function."""

    def test_perfect_scores_all_domains(self):
        """Perfect scores in all domains should give 100."""
        domain_scores = {
            'network': 100,
            'tls': 100,
            'http': 100,
            'dns': 100,
        }
        overall = compute_overall_score(domain_scores)
        assert overall == 100.0

    def test_zero_scores_all_domains(self):
        """Zero scores in all domains should give 0."""
        domain_scores = {
            'network': 0,
            'tls': 0,
            'http': 0,
            'dns': 0,
        }
        overall = compute_overall_score(domain_scores)
        assert overall == 0.0

    def test_weighted_calculation(self):
        """Verify weighted calculation formula."""
        domain_scores = {
            'network': 60,   # 0.25 * 60 = 15
            'tls': 80,       # 0.30 * 80 = 24
            'http': 70,      # 0.25 * 70 = 17.5
            'dns': 90,       # 0.20 * 90 = 18
        }
        overall = compute_overall_score(domain_scores)
        expected = (60 * 0.25) + (80 * 0.30) + (70 * 0.25) + (90 * 0.20)
        assert overall == expected

    def test_missing_domain_defaults_to_100(self):
        """Missing domain should default to 100."""
        domain_scores = {
            'network': 50,
            # tls, http, dns missing
        }
        overall = compute_overall_score(domain_scores)
        expected = (50 * 0.25) + (100 * 0.30) + (100 * 0.25) + (100 * 0.20)
        assert overall == expected


# =============================================================================
# GRADE TESTS
# =============================================================================

class TestComputeGrade:
    """Tests for compute_grade function."""

    def test_grade_a_at_90(self):
        """Score of 90 should be A."""
        assert compute_grade(90.0) == 'A'

    def test_grade_a_at_100(self):
        """Score of 100 should be A."""
        assert compute_grade(100.0) == 'A'

    def test_grade_b_at_75(self):
        """Score of 75 should be B."""
        assert compute_grade(75.0) == 'B'

    def test_grade_b_at_89(self):
        """Score of 89 should be B."""
        assert compute_grade(89.9) == 'B'

    def test_grade_c_at_60(self):
        """Score of 60 should be C."""
        assert compute_grade(60.0) == 'C'

    def test_grade_c_at_74(self):
        """Score of 74 should be C."""
        assert compute_grade(74.9) == 'C'

    def test_grade_d_at_45(self):
        """Score of 45 should be D."""
        assert compute_grade(45.0) == 'D'

    def test_grade_d_at_59(self):
        """Score of 59 should be D."""
        assert compute_grade(59.9) == 'D'

    def test_grade_f_at_44(self):
        """Score of 44 should be F."""
        assert compute_grade(44.9) == 'F'

    def test_grade_f_at_0(self):
        """Score of 0 should be F."""
        assert compute_grade(0.0) == 'F'


# =============================================================================
# OWASP COVERAGE TESTS
# =============================================================================

class TestComputeOwaspCoverage:
    """Tests for compute_owasp_coverage function."""

    def test_empty_findings_all_pass(self, empty_findings):
        """No findings should result in all pass statuses."""
        coverage = compute_owasp_coverage(empty_findings)
        assert len(coverage) == 10  # OWASP Top 10
        for item in coverage:
            assert item['status'] == 'pass'
            assert item['finding_count'] == 0

    def test_findings_with_owasp_mapping(self, sample_findings):
        """Findings with OWASP IDs should be counted correctly."""
        coverage = compute_owasp_coverage(sample_findings)
        coverage_dict = {item['owasp_id']: item for item in coverage}
        
        # A01 should have 1 finding (CORS)
        assert coverage_dict['A01']['finding_count'] == 1
        assert coverage_dict['A01']['status'] == 'fail'
        
        # A02 should have 2 findings (TLS issues)
        assert coverage_dict['A02']['finding_count'] == 2
        assert coverage_dict['A02']['status'] == 'fail'
        
        # A05 should have 3 findings (CSP, SPF, Server header)
        assert coverage_dict['A05']['finding_count'] == 3
        assert coverage_dict['A05']['status'] == 'fail'
        
        # A07 should have 2 findings (Telnet, FTP)
        assert coverage_dict['A07']['finding_count'] == 2
        assert coverage_dict['A07']['status'] == 'fail'
        
        # A08 should have 1 finding (Hardcoded API key)
        assert coverage_dict['A08']['finding_count'] == 1
        assert coverage_dict['A08']['status'] == 'fail'

    def test_all_categories_present(self, empty_findings):
        """All 10 OWASP categories should be present."""
        coverage = compute_owasp_coverage(empty_findings)
        owasp_ids = [item['owasp_id'] for item in coverage]
        expected_ids = ['A01', 'A02', 'A03', 'A04', 'A05', 
                        'A06', 'A07', 'A08', 'A09', 'A10']
        assert sorted(owasp_ids) == sorted(expected_ids)


# =============================================================================
# SUMMARY TESTS
# =============================================================================

class TestComputeSummary:
    """Tests for compute_summary function."""

    def test_empty_findings_summary(self, empty_findings):
        """Empty findings should return zeroed summary."""
        summary = compute_summary(empty_findings)
        assert summary['total_findings'] == 0
        assert summary['highest_cvss'] == 0.0
        assert summary['highest_cvss_finding'] == ''
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            assert summary['by_severity'][severity] == 0

    def test_severity_counts(self, sample_findings):
        """Summary should count findings by severity correctly."""
        summary = compute_summary(sample_findings)
        assert summary['by_severity']['critical'] == 2
        assert summary['by_severity']['high'] == 4
        assert summary['by_severity']['medium'] == 1
        assert summary['by_severity']['low'] == 2
        assert summary['by_severity']['info'] == 0

    def test_total_findings_count(self, sample_findings):
        """Total findings should be counted correctly."""
        summary = compute_summary(sample_findings)
        assert summary['total_findings'] == 9

    def test_highest_cvss_tracking(self, sample_findings):
        """Highest CVSS should be tracked correctly."""
        summary = compute_summary(sample_findings)
        assert summary['highest_cvss'] == 9.8
        assert summary['highest_cvss_finding'] == "Hardcoded API key found"


# =============================================================================
# MAIN ENTRY POINT TESTS
# =============================================================================

class TestGenerateScoreReport:
    """Tests for generate_score_report function."""

    def test_report_structure(self, sample_findings):
        """Report should have required keys."""
        report = generate_score_report(sample_findings)
        assert 'scores' in report
        assert 'owasp_coverage' in report
        assert 'summary' in report

    def test_scores_structure(self, sample_findings):
        """Scores should have all required domains and overall."""
        report = generate_score_report(sample_findings)
        scores = report['scores']
        assert 'network' in scores
        assert 'tls' in scores
        assert 'http' in scores
        assert 'dns' in scores
        assert 'static' in scores
        assert 'weighted_overall' in scores
        assert 'grade' in scores

    def test_empty_findings_perfect_score(self, empty_findings):
        """Empty findings should result in perfect scores."""
        report = generate_score_report(empty_findings)
        assert report['scores']['network'] == 100
        assert report['scores']['tls'] == 100
        assert report['scores']['http'] == 100
        assert report['scores']['dns'] == 100
        assert report['scores']['weighted_overall'] == 100.0
        assert report['scores']['grade'] == 'A'

    def test_domain_scores_calculated(self, sample_findings):
        """Domain scores should reflect findings."""
        report = generate_score_report(sample_findings)
        # Network: critical (-25) + high (-15) = 60
        assert report['scores']['network'] == 60
        # TLS: high (-15) + high (-15) = 70
        assert report['scores']['tls'] == 70
        # HTTP: medium (-8) + high (-15) + low (-3) = 74
        assert report['scores']['http'] == 74
        # DNS: low (-3) = 97
        assert report['scores']['dns'] == 97

    def test_weighted_overall_rounded(self, sample_findings):
        """Weighted overall should be rounded to 2 decimals."""
        report = generate_score_report(sample_findings)
        weighted = report['scores']['weighted_overall']
        # Check it's properly rounded
        assert weighted == round(weighted, 2)


# =============================================================================
# DETERMINISM TESTS
# =============================================================================

class TestScoringDeterminism:
    """Tests to verify scoring is deterministic."""

    def test_scoring_determinism(self, sample_findings):
        """Verify scoring is deterministic."""
        result1 = generate_score_report(sample_findings)
        result2 = generate_score_report(sample_findings)
        assert result1 == result2, "Scoring must be deterministic"

    def test_domain_score_determinism(self, sample_findings):
        """Verify domain scoring is deterministic."""
        network_findings = [f for f in sample_findings if f.domain == 'network']
        score1 = compute_domain_score(network_findings)
        score2 = compute_domain_score(network_findings)
        assert score1 == score2

    def test_owasp_coverage_determinism(self, sample_findings):
        """Verify OWASP coverage is deterministic."""
        coverage1 = compute_owasp_coverage(sample_findings)
        coverage2 = compute_owasp_coverage(sample_findings)
        assert coverage1 == coverage2

    def test_summary_determinism(self, sample_findings):
        """Verify summary is deterministic."""
        summary1 = compute_summary(sample_findings)
        summary2 = compute_summary(sample_findings)
        assert summary1 == summary2

    def test_repeated_calls_same_result(self, sample_findings):
        """Multiple calls should produce identical results."""
        results = [generate_score_report(sample_findings) for _ in range(10)]
        for result in results[1:]:
            assert result == results[0]


# =============================================================================
# CVSS PARSING TESTS
# =============================================================================

class TestParseCvssVector:
    """Tests for parse_cvss_vector function."""

    def test_parse_full_vector(self):
        """Parse a complete CVSS vector."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        components = parse_cvss_vector(vector)
        assert components['AV'] == 'N'
        assert components['AC'] == 'L'
        assert components['PR'] == 'N'
        assert components['UI'] == 'N'
        assert components['S'] == 'U'
        assert components['C'] == 'H'
        assert components['I'] == 'H'
        assert components['A'] == 'N'

    def test_parse_without_prefix(self):
        """Parse vector without CVSS prefix."""
        vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        components = parse_cvss_vector(vector)
        assert components['AV'] == 'N'
        assert components['C'] == 'H'

    def test_parse_cvss_30_prefix(self):
        """Parse vector with CVSS 3.0 prefix."""
        vector = "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L"
        components = parse_cvss_vector(vector)
        assert components['AV'] == 'A'
        assert components['S'] == 'C'


# =============================================================================
# CVSS SCORE CALCULATION TESTS
# =============================================================================

class TestCalculateCvssBaseScore:
    """Tests for calculate_cvss_base_score function."""

    def test_critical_severity_vector(self):
        """Test critical severity CVSS vector."""
        # Network, Low complexity, No privs, No interaction, Unchanged scope, High CIA
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = calculate_cvss_base_score(vector)
        assert 9.0 <= score <= 10.0

    def test_zero_impact_vector(self):
        """Test vector with no impact should score 0."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        score = calculate_cvss_base_score(vector)
        assert score == 0.0

    def test_scope_changed_affects_score(self):
        """Test that changed scope affects score."""
        # Same vector but with changed scope
        unchanged = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        changed = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"
        score_unchanged = calculate_cvss_base_score(unchanged)
        score_changed = calculate_cvss_base_score(changed)
        # Changed scope should give higher or equal score
        assert score_changed >= score_unchanged

    def test_known_cvss_score(self):
        """Test against a known CVSS score (Heartbleed-like)."""
        # Heartbleed: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        score = calculate_cvss_base_score(vector)
        assert 7.0 <= score <= 8.0


# =============================================================================
# CVSS VECTOR GENERATION TESTS
# =============================================================================

class TestGenerateCvssVector:
    """Tests for generate_cvss_vector function."""

    def test_default_values(self):
        """Test default values generate valid vector."""
        vector = generate_cvss_vector()
        assert vector.startswith("CVSS:3.1/")
        assert "/AV:N/" in vector
        assert "/AC:L/" in vector
        assert "/PR:N/" in vector
        assert "/UI:N/" in vector
        assert "/S:U/" in vector

    def test_custom_values(self):
        """Test custom values generate correct vector."""
        vector = generate_cvss_vector(
            attack_vector='A',
            attack_complexity='H',
            privileges_required='L',
            user_interaction='R',
            scope='C',
            confidentiality='L',
            integrity='H',
            availability='N',
        )
        assert "/AV:A/" in vector
        assert "/AC:H/" in vector
        assert "/PR:L/" in vector
        assert "/UI:R/" in vector
        assert "/S:C/" in vector
        assert "/C:L/" in vector
        assert "/I:H/" in vector
        assert "/A:N" in vector

    def test_roundtrip(self):
        """Test that generated vector can be parsed back."""
        vector = generate_cvss_vector(
            attack_vector='L',
            attack_complexity='H',
            privileges_required='H',
            user_interaction='R',
            scope='U',
            confidentiality='H',
            integrity='L',
            availability='N',
        )
        components = parse_cvss_vector(vector)
        assert components['AV'] == 'L'
        assert components['AC'] == 'H'
        assert components['PR'] == 'H'
        assert components['UI'] == 'R'
        assert components['S'] == 'U'
        assert components['C'] == 'H'
        assert components['I'] == 'L'
        assert components['A'] == 'N'


# =============================================================================
# CVSS BREAKDOWN TESTS
# =============================================================================

class TestGetCvssBreakdown:
    """Tests for get_cvss_breakdown function."""

    def test_breakdown_labels(self):
        """Test that breakdown returns human-readable labels."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        breakdown = get_cvss_breakdown(vector)
        assert breakdown['attack_vector'] == 'Network'
        assert breakdown['attack_complexity'] == 'Low'
        assert breakdown['privileges_required'] == 'None'
        assert breakdown['user_interaction'] == 'None'
        assert breakdown['scope'] == 'Unchanged'
        assert breakdown['confidentiality'] == 'High'
        assert breakdown['integrity'] == 'High'
        assert breakdown['availability'] == 'None'

    def test_breakdown_all_values(self):
        """Test breakdown for various vector values."""
        vector = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L"
        breakdown = get_cvss_breakdown(vector)
        assert breakdown['attack_vector'] == 'Physical'
        assert breakdown['attack_complexity'] == 'High'
        assert breakdown['privileges_required'] == 'High'
        assert breakdown['user_interaction'] == 'Required'
        assert breakdown['scope'] == 'Changed'
        assert breakdown['confidentiality'] == 'Low'
        assert breakdown['integrity'] == 'Low'
        assert breakdown['availability'] == 'Low'


# =============================================================================
# SEVERITY FROM CVSS TESTS
# =============================================================================

class TestGetSeverityFromCvss:
    """Tests for get_severity_from_cvss function."""

    def test_critical_severity(self):
        """Score >= 9.0 should be critical."""
        assert get_severity_from_cvss(9.0) == 'critical'
        assert get_severity_from_cvss(10.0) == 'critical'

    def test_high_severity(self):
        """Score 7.0-8.9 should be high."""
        assert get_severity_from_cvss(7.0) == 'high'
        assert get_severity_from_cvss(8.9) == 'high'

    def test_medium_severity(self):
        """Score 4.0-6.9 should be medium."""
        assert get_severity_from_cvss(4.0) == 'medium'
        assert get_severity_from_cvss(6.9) == 'medium'

    def test_low_severity(self):
        """Score 0.1-3.9 should be low."""
        assert get_severity_from_cvss(0.1) == 'low'
        assert get_severity_from_cvss(3.9) == 'low'

    def test_info_severity(self):
        """Score 0.0 should be info."""
        assert get_severity_from_cvss(0.0) == 'info'


# =============================================================================
# UTILITY FUNCTION TESTS
# =============================================================================

class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_get_findings_by_domain(self, sample_findings):
        """Test filtering findings by domain."""
        network = get_findings_by_domain(sample_findings, 'network')
        assert len(network) == 2
        assert all(f.domain == 'network' for f in network)

    def test_get_findings_by_severity(self, sample_findings):
        """Test filtering findings by severity."""
        critical = get_findings_by_severity(sample_findings, 'critical')
        assert len(critical) == 2
        assert all(f.severity == 'critical' for f in critical)

    def test_get_findings_by_owasp(self, sample_findings):
        """Test filtering findings by OWASP category."""
        a07 = get_findings_by_owasp(sample_findings, 'A07')
        assert len(a07) == 2
        assert all(f.owasp_id == 'A07' for f in a07)

    def test_sort_findings_by_cvss_descending(self, sample_findings):
        """Test sorting findings by CVSS score descending."""
        sorted_findings = sort_findings_by_cvss(sample_findings)
        for i in range(len(sorted_findings) - 1):
            assert sorted_findings[i].cvss_score >= sorted_findings[i + 1].cvss_score

    def test_sort_findings_by_cvss_ascending(self, sample_findings):
        """Test sorting findings by CVSS score ascending."""
        sorted_findings = sort_findings_by_cvss(sample_findings, descending=False)
        for i in range(len(sorted_findings) - 1):
            assert sorted_findings[i].cvss_score <= sorted_findings[i + 1].cvss_score


# =============================================================================
# EDGE CASE TESTS
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases."""

    def test_findings_with_no_owasp_id(self):
        """Test findings without OWASP ID."""
        findings = [
            Finding(domain="network", severity="high", title="Test", owasp_id=""),
        ]
        coverage = compute_owasp_coverage(findings)
        # All categories should pass since no valid OWASP ID
        for item in coverage:
            assert item['finding_count'] == 0

    def test_mixed_valid_invalid_owasp_ids(self):
        """Test mix of valid and invalid OWASP IDs."""
        findings = [
            Finding(domain="network", severity="high", title="Test1", owasp_id="A01"),
            Finding(domain="network", severity="high", title="Test2", owasp_id=""),
            Finding(domain="network", severity="high", title="Test3", owasp_id="A01"),
        ]
        coverage = compute_owasp_coverage(findings)
        coverage_dict = {item['owasp_id']: item for item in coverage}
        assert coverage_dict['A01']['finding_count'] == 2

    def test_very_high_penalty_count(self):
        """Test with many findings to verify floor at 0."""
        findings = [
            Finding(domain="network", severity="critical", title=f"Test{i}")
            for i in range(100)
        ]
        score = compute_domain_score(findings)
        assert score == 0

    def test_empty_cvss_vector(self):
        """Test parsing empty CVSS vector."""
        components = parse_cvss_vector("")
        assert components == {}

    def test_malformed_cvss_vector(self):
        """Test parsing malformed CVSS vector."""
        vector = "not a valid vector"
        components = parse_cvss_vector(vector)
        # Should handle gracefully without raising
        assert isinstance(components, dict)
