#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="security-reports"
REPORT_FILE="${REPORT_DIR}/security-tool-comparison.md"
SEMGREP_SARIF="${REPORT_DIR}/semgrep.sarif"
SONAR_JSON="${REPORT_DIR}/sonar-issues.json"
SONAR_HOTSPOTS_JSON="${REPORT_DIR}/sonar-hotspots.json"

mkdir -p "${REPORT_DIR}"

sarif_count() {
  local file="$1"
  if [[ -f "${file}" ]]; then
    jq '[.runs[]?.results[]?] | length' "${file}"
  else
    echo 0
  fi
}

sarif_files() {
  local file="$1"
  if [[ -f "${file}" ]]; then
    jq -r '.runs[]?.results[]?.locations[]?.physicalLocation?.artifactLocation?.uri? // empty' "${file}"
  fi
}

sonar_count() {
  if [[ -f "${SONAR_JSON}" ]]; then
    jq '.issues | length' "${SONAR_JSON}"
  else
    echo 0
  fi
}

sonar_hotspot_count() {
  if [[ -f "${SONAR_HOTSPOTS_JSON}" ]]; then
    jq '.hotspots | length' "${SONAR_HOTSPOTS_JSON}"
  else
    echo 0
  fi
}

sonar_files() {
  if [[ -f "${SONAR_JSON}" ]]; then
    jq -r '.issues[]?.component? // empty | sub("^.*:"; "")' "${SONAR_JSON}"
  fi
}

sonar_hotspot_files() {
  if [[ -f "${SONAR_HOTSPOTS_JSON}" ]]; then
    jq -r '.hotspots[]?.component? // empty | sub("^.*:"; "")' "${SONAR_HOTSPOTS_JSON}"
  fi
}

escape_md() {
  local value="${1:-}"
  value="${value//$'\n'/ }"
  value="${value//$'\r'/ }"
  value="${value//|/\\|}"
  echo "${value}"
}

sarif_details_for_file() {
  local file="$1"
  local expected_file="$2"

  if [[ ! -f "${file}" ]]; then
    echo "No findings"
    return
  fi

  local details
  details="$(jq -r --arg expected_file "${expected_file}" '
    def normalize_path:
      tostring
      | sub("^file://"; "")
      | sub("^/src/"; "")
      | sub("^/github/workspace/"; "")
      | sub("^\\./"; "");

    def matches_expected($expected):
      (normalize_path == $expected) or (normalize_path | endswith($expected));

    def rule_lookup($run; $id):
      ($run.tool.driver.rules // [])
      | map(select(.id == $id))
      | first
      | .shortDescription.text // .fullDescription.text // "";

    [
      .runs[]? as $run
      | $run.results[]?
      | select([
          .locations[]?.physicalLocation?.artifactLocation?.uri?
        ] | any(matches_expected($expected_file)))
      | {
          rule: (.ruleId // "unknown-rule"),
          level: (.level // "unknown"),
          line: (.locations[0].physicalLocation.region.startLine // "?"),
          message: (.message.text // rule_lookup($run; .ruleId) // "")
        }
      | "\(.rule) [\(.level)] line \(.line): \(.message)"
    ][0:3] | join("<br>")
  ' "${file}")"

  if [[ -n "${details}" ]]; then
    escape_md "${details}"
  else
    echo "No findings"
  fi
}

sarif_result_count_for_file() {
  local file="$1"
  local expected_file="$2"

  if [[ ! -f "${file}" ]]; then
    echo 0
    return
  fi

  jq -r --arg expected_file "${expected_file}" '
    def normalize_path:
      tostring
      | sub("^file://"; "")
      | sub("^/src/"; "")
      | sub("^/github/workspace/"; "")
      | sub("^\\./"; "");

    def matches_expected($expected):
      (normalize_path == $expected) or (normalize_path | endswith($expected));

    [
      .runs[]?.results[]?
      | select([
          .locations[]?.physicalLocation?.artifactLocation?.uri?
        ] | any(matches_expected($expected_file)))
    ] | length
  ' "${file}"
}

codeql_details_for_file() {
  local expected_file="$1"
  local combined_details=""

  while IFS= read -r sarif; do
    local details
    details="$(sarif_details_for_file "${sarif}" "${expected_file}")"
    if [[ "${details}" != "No findings" ]]; then
      combined_details="${combined_details}<br>${details}"
    fi
  done < <(find "${REPORT_DIR}/codeql-results" -type f -name '*.sarif' 2>/dev/null | sort)

  combined_details="${combined_details#<br>}"
  if [[ -n "${combined_details}" ]]; then
    echo "${combined_details}"
  else
    echo "No findings"
  fi
}

codeql_result_count_for_file() {
  local expected_file="$1"
  local count=0

  while IFS= read -r sarif; do
    count=$((count + $(sarif_result_count_for_file "${sarif}" "${expected_file}")))
  done < <(find "${REPORT_DIR}/codeql-results" -type f -name '*.sarif' 2>/dev/null | sort)

  echo "${count}"
}

sonar_issue_details_for_file() {
  local expected_file="$1"

  if [[ ! -f "${SONAR_JSON}" ]]; then
    echo ""
    return
  fi

  jq -r --arg expected_file "${expected_file}" '
    [
      .issues[]?
      | select((.component? // "" | sub("^.*:"; "")) == $expected_file)
      | "\(.rule // "unknown-rule") [\(.severity // "unknown")/\(.type // "unknown")] line \(.line // "?"): \(.message // "")"
    ][0:3] | join("<br>")
  ' "${SONAR_JSON}"
}

sonar_issue_count_for_file() {
  local expected_file="$1"

  if [[ ! -f "${SONAR_JSON}" ]]; then
    echo 0
    return
  fi

  jq -r --arg expected_file "${expected_file}" '
    [
      .issues[]?
      | select((.component? // "" | sub("^.*:"; "")) == $expected_file)
    ] | length
  ' "${SONAR_JSON}"
}

sonar_hotspot_details_for_file() {
  local expected_file="$1"

  if [[ ! -f "${SONAR_HOTSPOTS_JSON}" ]]; then
    echo ""
    return
  fi

  jq -r --arg expected_file "${expected_file}" '
    [
      .hotspots[]?
      | select((.component? // "" | sub("^.*:"; "")) == $expected_file)
      | "\(.ruleKey // "unknown-rule") [HOTSPOT/\(.status // "unknown")] line \(.line // "?"): \(.message // "")"
    ][0:3] | join("<br>")
  ' "${SONAR_HOTSPOTS_JSON}"
}

sonar_hotspot_count_for_file() {
  local expected_file="$1"

  if [[ ! -f "${SONAR_HOTSPOTS_JSON}" ]]; then
    echo 0
    return
  fi

  jq -r --arg expected_file "${expected_file}" '
    [
      .hotspots[]?
      | select((.component? // "" | sub("^.*:"; "")) == $expected_file)
    ] | length
  ' "${SONAR_HOTSPOTS_JSON}"
}

sonar_details_for_file() {
  local expected_file="$1"
  local issue_details hotspot_details combined_details

  issue_details="$(sonar_issue_details_for_file "${expected_file}")"
  hotspot_details="$(sonar_hotspot_details_for_file "${expected_file}")"
  combined_details="${issue_details}"
  if [[ -n "${hotspot_details}" ]]; then
    if [[ -n "${combined_details}" ]]; then
      combined_details="${combined_details}<br>${hotspot_details}"
    else
      combined_details="${hotspot_details}"
    fi
  fi

  if [[ -n "${combined_details}" ]]; then
    escape_md "${combined_details}"
  else
    echo "No findings"
  fi
}

sonar_result_count_for_file() {
  local expected_file="$1"
  echo $(( \
    $(sonar_issue_count_for_file "${expected_file}") + \
    $(sonar_hotspot_count_for_file "${expected_file}") \
  ))
}

CODEQL_COUNT=0
CODEQL_FILES=""
while IFS= read -r sarif; do
  count="$(sarif_count "${sarif}")"
  CODEQL_COUNT=$((CODEQL_COUNT + count))
  CODEQL_FILES="${CODEQL_FILES}"$'\n'"$(sarif_files "${sarif}")"
done < <(find "${REPORT_DIR}/codeql-results" -type f -name '*.sarif' 2>/dev/null | sort)

SEMGREP_COUNT="$(sarif_count "${SEMGREP_SARIF}")"
SEMGREP_FILES="$(sarif_files "${SEMGREP_SARIF}")"
SONAR_COUNT="$(sonar_count)"
SONAR_HOTSPOT_COUNT="$(sonar_hotspot_count)"
SONAR_FILES="$(sonar_files)"
SONAR_HOTSPOT_FILES="$(sonar_hotspot_files)"
SONAR_ALL_FILES="${SONAR_FILES}"$'\n'"${SONAR_HOTSPOT_FILES}"

yes_no_from_count() {
  local count="$1"
  if (( count > 0 )); then
    echo "Yes"
  else
    echo "No"
  fi
}

write_classified_case_row() {
  local title="$1"
  local vulnerability_class="$2"
  local file="$3"
  local semgrep codeql sonar

  semgrep="$(yes_no_from_count "$(sarif_result_count_for_file "${SEMGREP_SARIF}" "${file}")")"
  codeql="$(yes_no_from_count "$(codeql_result_count_for_file "${file}")")"
  sonar="$(yes_no_from_count "$(sonar_result_count_for_file "${file}")")"

  printf '| %s | %s | `%s` | %s | %s | %s |\n' "${title}" "${vulnerability_class}" "${file}" "${semgrep}" "${codeql}" "${sonar}" >> "${REPORT_FILE}"
}

write_detail_row() {
  local title="$1"
  local file="$2"
  local semgrep_detail codeql_detail sonar_detail

  semgrep_detail="$(sarif_details_for_file "${SEMGREP_SARIF}" "${file}")"
  codeql_detail="$(codeql_details_for_file "${file}")"
  sonar_detail="$(sonar_details_for_file "${file}")"

  printf '| %s | `%s` | %s | %s | %s |\n' "${title}" "${file}" "${semgrep_detail}" "${codeql_detail}" "${sonar_detail}" >> "${REPORT_FILE}"
}

sum_semgrep_target_findings() {
  local count=0
  local expected_file

  for expected_file in "$@"; do
    count=$((count + $(sarif_result_count_for_file "${SEMGREP_SARIF}" "${expected_file}")))
  done

  echo "${count}"
}

sum_codeql_target_findings() {
  local count=0
  local expected_file

  for expected_file in "$@"; do
    count=$((count + $(codeql_result_count_for_file "${expected_file}")))
  done

  echo "${count}"
}

sum_sonar_target_findings() {
  local count=0
  local expected_file

  for expected_file in "$@"; do
    count=$((count + $(sonar_result_count_for_file "${expected_file}")))
  done

  echo "${count}"
}

STRUCTURAL_FILES=(
  "src/main/resources/templates/owners/ownerDetails.html"
  "src/main/resources/application.properties"
  "src/main/java/org/springframework/samples/petclinic/system/VulnerableFileDownloadController.java"
  "src/main/java/org/springframework/samples/petclinic/owner/VulnerableOwnerSearchController.java"
)

CONTEXTUAL_FILES=(
  "src/main/java/org/springframework/samples/petclinic/system/VulnerableAdminReportController.java"
  "src/main/java/org/springframework/samples/petclinic/system/VulnerableLoggingController.java"
)

ALL_EXPECTED_FILES=("${STRUCTURAL_FILES[@]}" "${CONTEXTUAL_FILES[@]}")

SONAR_TOTAL_COUNT=$((SONAR_COUNT + SONAR_HOTSPOT_COUNT))
SEMGREP_TARGET_FINDING_COUNT="$(sum_semgrep_target_findings "${ALL_EXPECTED_FILES[@]}")"
CODEQL_TARGET_FINDING_COUNT="$(sum_codeql_target_findings "${ALL_EXPECTED_FILES[@]}")"
SONAR_TARGET_FINDING_COUNT="$(sum_sonar_target_findings "${ALL_EXPECTED_FILES[@]}")"
SEMGREP_NON_TARGET_FINDING_COUNT=$((SEMGREP_COUNT - SEMGREP_TARGET_FINDING_COUNT))
CODEQL_NON_TARGET_FINDING_COUNT=$((CODEQL_COUNT - CODEQL_TARGET_FINDING_COUNT))
SONAR_NON_TARGET_FINDING_COUNT=$((SONAR_TOTAL_COUNT - SONAR_TARGET_FINDING_COUNT))

{
  echo "# Security Tool Comparison Report"
  echo
  echo "## Run Metadata"
  echo
  echo "| Field | Value |"
  echo "| --- | --- |"
  echo "| Commit | \`${GITHUB_SHA:-local}\` |"
  echo "| Branch/ref | \`${GITHUB_REF_NAME:-local}\` |"
  echo "| Generated at | \`$(date -u '+%Y-%m-%dT%H:%M:%SZ')\` |"
  echo
  echo "## Experimental Design"
  echo
  echo "| Dimension | Description |"
  echo "| --- | --- |"
  echo "| Subject system | Intentionally vulnerable Spring Petclinic codebase |"
  echo "| Compared tools | Semgrep, CodeQL, SonarCloud |"
  echo "| Evidence artifacts | \`semgrep.sarif\`, \`codeql-results/*.sarif\`, \`sonar-issues.json\`, \`sonar-hotspots.json\` |"
  echo "| Detection unit | File-level match against the file that contains the seeded vulnerability |"
  echo "| Count interpretation | Total exported findings cover the whole analyzed codebase; target-file findings cover only the seeded vulnerability files |"
  echo "| Match interpretation | A file-level match does not prove that the exact weakness was classified correctly |"
  echo
  echo "## Tool Configuration"
  echo
  echo "| Tool | Configuration |"
  echo "| --- | --- |"
  echo "| Semgrep | Public/default-style rulesets: \`p/security-audit\`, \`p/secrets\`, \`p/owasp-top-ten\`, \`p/java\`; no project-specific rules |"
  echo "| CodeQL | GitHub Java/Kotlin analysis with \`security-extended\` and \`security-and-quality\` query suites |"
  echo "| SonarCloud | Configured SonarCloud project quality profile; issues from \`api/issues/search\`; hotspots from \`api/hotspots/search\` |"
  echo
  echo "## Vulnerability Classification"
  echo
  echo "| Class | Operational definition | Seeded scenarios |"
  echo "| --- | --- | --- |"
  echo "| Structural | Vulnerabilities that can usually be identified through syntactic patterns, data-flow, source-to-sink relationships, or configuration inspection | Stored XSS, hardcoded secrets, path traversal, JPQL injection |"
  echo "| Contextual | Vulnerabilities that depend on application policy, business rules, intended authorization boundaries, or semantic interpretation of sensitive behavior | Missing admin authorization, sensitive data and user input in logs |"
  echo
  echo "## Finding Counts"
  echo
  echo "| Tool | Total exported findings | Findings in target files | Findings outside target files | Source artifact |"
  echo "| --- | ---: | ---: | ---: | --- |"
  echo "| Semgrep | ${SEMGREP_COUNT} | ${SEMGREP_TARGET_FINDING_COUNT} | ${SEMGREP_NON_TARGET_FINDING_COUNT} | \`semgrep.sarif\` |"
  echo "| CodeQL | ${CODEQL_COUNT} | ${CODEQL_TARGET_FINDING_COUNT} | ${CODEQL_NON_TARGET_FINDING_COUNT} | \`codeql-results/*.sarif\` |"
  echo "| SonarCloud | ${SONAR_TOTAL_COUNT} (${SONAR_COUNT} issues / ${SONAR_HOTSPOT_COUNT} hotspots) | ${SONAR_TARGET_FINDING_COUNT} | ${SONAR_NON_TARGET_FINDING_COUNT} | \`sonar-issues.json\`, \`sonar-hotspots.json\` |"
  echo
  echo "## Vulnerability-Level Detection Matrix"
  echo
  echo "| Vulnerability scenario | Class | File | Semgrep | CodeQL | SonarCloud |"
  echo "| --- | --- | --- | --- | --- | --- |"
} > "${REPORT_FILE}"

write_classified_case_row "Stored XSS via unsafe Thymeleaf rendering" "Structural" "src/main/resources/templates/owners/ownerDetails.html"
write_classified_case_row "Hardcoded fake secrets" "Structural" "src/main/resources/application.properties"
write_classified_case_row "Path traversal file download" "Structural" "src/main/java/org/springframework/samples/petclinic/system/VulnerableFileDownloadController.java"
write_classified_case_row "JPQL injection through string concatenation" "Structural" "src/main/java/org/springframework/samples/petclinic/owner/VulnerableOwnerSearchController.java"
write_classified_case_row "Missing admin authorization / business logic weakness" "Contextual" "src/main/java/org/springframework/samples/petclinic/system/VulnerableAdminReportController.java"
write_classified_case_row "Sensitive data and user input in logs" "Contextual" "src/main/java/org/springframework/samples/petclinic/system/VulnerableLoggingController.java"

{
  echo
  echo "## Finding Evidence by Target File"
  echo
  echo "| Vulnerability scenario | File | Semgrep details | CodeQL details | SonarCloud details |"
  echo "| --- | --- | --- | --- | --- |"
} >> "${REPORT_FILE}"

write_detail_row "Stored XSS via unsafe Thymeleaf rendering" "src/main/resources/templates/owners/ownerDetails.html"
write_detail_row "Hardcoded fake secrets" "src/main/resources/application.properties"
write_detail_row "Path traversal file download" "src/main/java/org/springframework/samples/petclinic/system/VulnerableFileDownloadController.java"
write_detail_row "JPQL injection through string concatenation" "src/main/java/org/springframework/samples/petclinic/owner/VulnerableOwnerSearchController.java"
write_detail_row "Missing admin authorization / business logic weakness" "src/main/java/org/springframework/samples/petclinic/system/VulnerableAdminReportController.java"
write_detail_row "Sensitive data and user input in logs" "src/main/java/org/springframework/samples/petclinic/system/VulnerableLoggingController.java"
