"""Consistency and structural tests for security catalog and SARIF fixture.

Verifies:
1. Catalog JSON parses successfully.
2. SARIF JSON parses successfully.
3. SARIF version is 2.1.0.
4. Catalog contains exactly 8 findings with unique IDs.
5. SARIF rules contain the required IDs (SFV-001 to SFV-008).
6. SARIF results contain exactly one result per required finding ID.
7. Catalog IDs and SARIF rule/result IDs agree.
8. Severity values and descriptions agree between catalog and SARIF.
9. Every referenced source file exists within the repository.
10. Every start line is a positive integer and within actual file line count.
11. Every end line is valid (>= start line and <= total lines).
12. Every finding points to its intended code construct (not just comments).
13. Paths remain relative to repo root (no absolute paths or path traversal).
"""

import json
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = REPO_ROOT / "security" / "findings-catalog.json"
SARIF_PATH = REPO_ROOT / "fixtures" / "securefix-vuln-lab.sarif"

EXPECTED_RULE_IDS = [f"SFV-00{i}" for i in range(1, 9)]

SEVERITY_TO_SARIF_LEVEL = {
    "High": "error",
    "Medium": "warning",
    "Low": "note",
}


@pytest.fixture(scope="module")
def catalog_data():
    """Load and parse the authoritative findings catalog."""
    assert CATALOG_PATH.exists(), f"Missing catalog file at {CATALOG_PATH}"
    with open(CATALOG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def sarif_data():
    """Load and parse the SARIF 2.1.0 fixture."""
    assert SARIF_PATH.exists(), f"Missing SARIF fixture file at {SARIF_PATH}"
    with open(SARIF_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def test_1_and_2_json_parsing(catalog_data, sarif_data):
    """1 & 2. Verify catalog and SARIF parse successfully as valid JSON dictionaries."""
    assert isinstance(catalog_data, dict)
    assert isinstance(sarif_data, dict)


def test_3_sarif_version(sarif_data):
    """3. Verify SARIF version is 2.1.0 and schema URL is present."""
    assert sarif_data.get("version") == "2.1.0"
    assert "$schema" in sarif_data
    assert "sarif-2.1.0" in sarif_data["$schema"]


def test_4_catalog_contains_eight_unique_findings(catalog_data):
    """4. Verify catalog contains exactly eight findings with unique IDs."""
    findings = catalog_data.get("findings", [])
    assert len(findings) == 8
    finding_ids = [f["id"] for f in findings]
    assert len(set(finding_ids)) == 8
    assert set(finding_ids) == set(EXPECTED_RULE_IDS)


def test_5_sarif_rules_contain_required_ids(sarif_data):
    """5. Verify SARIF tool driver rules declare all eight required rule IDs."""
    runs = sarif_data.get("runs", [])
    assert len(runs) >= 1
    rules = runs[0].get("tool", {}).get("driver", {}).get("rules", [])
    assert len(rules) == 8
    rule_ids = [r["id"] for r in rules]
    assert set(rule_ids) == set(EXPECTED_RULE_IDS)


def test_6_sarif_results_contain_one_result_per_id(sarif_data):
    """6. Verify SARIF results contain exactly one result per required finding ID."""
    results = sarif_data["runs"][0].get("results", [])
    assert len(results) == 8
    result_ids = [r["ruleId"] for r in results]
    assert len(set(result_ids)) == 8
    assert set(result_ids) == set(EXPECTED_RULE_IDS)


def test_7_catalog_and_sarif_ids_agree(catalog_data, sarif_data):
    """7. Verify catalog IDs and SARIF rule & result IDs agree."""
    cat_ids = sorted([f["id"] for f in catalog_data["findings"]])
    sarif_rule_ids = sorted([r["id"] for r in sarif_data["runs"][0]["tool"]["driver"]["rules"]])
    sarif_result_ids = sorted([r["ruleId"] for r in sarif_data["runs"][0]["results"]])

    assert cat_ids == EXPECTED_RULE_IDS
    assert sarif_rule_ids == EXPECTED_RULE_IDS
    assert sarif_result_ids == EXPECTED_RULE_IDS


def test_8_severity_and_level_consistency(catalog_data, sarif_data):
    """8. Verify severity values and SARIF levels correspond consistently."""
    cat_by_id = {f["id"]: f for f in catalog_data["findings"]}
    sarif_rules_by_id = {r["id"]: r for r in sarif_data["runs"][0]["tool"]["driver"]["rules"]}
    sarif_results_by_id = {r["ruleId"]: r for r in sarif_data["runs"][0]["results"]}

    for fid in EXPECTED_RULE_IDS:
        cat_finding = cat_by_id[fid]
        expected_level = SEVERITY_TO_SARIF_LEVEL[cat_finding["severity"]]
        assert cat_finding["sarif_level"] == expected_level

        sarif_rule = sarif_rules_by_id[fid]
        assert sarif_rule["defaultConfiguration"]["level"] == expected_level

        sarif_result = sarif_results_by_id[fid]
        assert sarif_result["level"] == expected_level


def test_9_10_11_13_file_paths_and_line_ranges(catalog_data, sarif_data):
    """9, 10, 11, 13. Verify source paths, line ranges, and safe repository-relative paths."""
    cat_by_id = {f["id"]: f for f in catalog_data["findings"]}
    sarif_results_by_id = {r["ruleId"]: r for r in sarif_data["runs"][0]["results"]}

    for fid in EXPECTED_RULE_IDS:
        cat_entry = cat_by_id[fid]
        sarif_res = sarif_results_by_id[fid]

        # Check repository-relative paths (13)
        cat_rel_path = cat_entry["file_path"]
        assert not cat_rel_path.startswith("/") and not cat_rel_path.startswith("\\")
        assert ".." not in cat_rel_path
        assert "\\" not in cat_rel_path  # Consistent forward slashes

        sarif_loc = sarif_res["locations"][0]["physicalLocation"]
        sarif_rel_path = sarif_loc["artifactLocation"]["uri"]
        assert cat_rel_path == sarif_rel_path

        # Verify target file exists within repo (9)
        abs_target_file = REPO_ROOT / cat_rel_path
        assert abs_target_file.is_file(), f"Target source file {abs_target_file} does not exist"

        with open(abs_target_file, "r", encoding="utf-8") as f:
            total_lines = len(f.readlines())

        # Check positive integer start lines and valid ranges (10 & 11)
        start_line = cat_entry["start_line"]
        end_line = cat_entry.get("end_line", start_line)
        sarif_region = sarif_loc["region"]

        assert isinstance(start_line, int) and start_line > 0
        assert isinstance(end_line, int) and end_line >= start_line
        assert start_line <= total_lines
        assert end_line <= total_lines

        assert sarif_region["startLine"] == start_line
        assert sarif_region.get("endLine", start_line) == end_line


def test_12_findings_map_to_intended_code_constructs(catalog_data):
    """12. Verify that each finding points to actual implementation code rather than comments."""
    expected_constructs = {
        "SFV-001": ["get_task_by_id", "return task"],
        "SFV-002": ["sql_query", "title LIKE", "cursor.execute(sql_query)"],
        "SFV-003": ["eval(filter_expr"],
        "SFV-004": ["CORSMiddleware", 'allow_origins=["*"]'],
        "SFV-005": ["JSONResponse", '"diagnostic"'],
        "SFV-006": ["security_headers_middleware", "return response"],
        "SFV-007": ["DEMO_API_KEY", '"demo-only-not-a-real-secret"'],
        "SFV-008": ['"version": settings.APP_VERSION'],
    }

    for finding in catalog_data["findings"]:
        fid = finding["id"]
        rel_path = finding["file_path"]
        start_line = finding["start_line"]
        end_line = finding.get("end_line", start_line)

        abs_file = REPO_ROOT / rel_path
        with open(abs_file, "r", encoding="utf-8") as f:
            all_lines = f.readlines()

        target_slice = "".join(all_lines[start_line - 1 : end_line])
        expected_patterns = expected_constructs[fid]

        for pattern in expected_patterns:
            assert pattern in target_slice, (
                f"Finding {fid} at {rel_path}:{start_line}-{end_line} does not contain "
                f"expected construct '{pattern}'. Content was:\n{target_slice}"
            )
