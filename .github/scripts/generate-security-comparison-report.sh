#!/usr/bin/env bash
set -euo pipefail

REPORT_DIR="security-reports"
REPORT_FILE="${REPORT_DIR}/security-tool-comparison.md"
SEMGREP_SARIF="${REPORT_DIR}/semgrep.sarif"
SONAR_JSON="${REPORT_DIR}/sonar-issues.json"

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

sonar_files() {
  if [[ -f "${SONAR_JSON}" ]]; then
    jq -r '.issues[]?.component? // empty | sub("^.*:"; "")' "${SONAR_JSON}"
  fi
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
SONAR_FILES="$(sonar_files)"

detected() {
  local files="$1"
  local expected_file="$2"
  if grep -Fq "${expected_file}" <<< "${files}"; then
    echo "Yes"
  else
    echo "No"
  fi
}

write_case_row() {
  local title="$1"
  local file="$2"
  local semgrep codeql sonar

  semgrep="$(detected "${SEMGREP_FILES}" "${file}")"
  codeql="$(detected "${CODEQL_FILES}" "${file}")"
  sonar="$(detected "${SONAR_FILES}" "${file}")"

  printf '| %s | `%s` | %s | %s | %s |\n' "${title}" "${file}" "${semgrep}" "${codeql}" "${sonar}" >> "${REPORT_FILE}"
}

{
  echo "# Security Tool Comparison Report"
  echo
  echo "Commit: \`${GITHUB_SHA:-local}\`"
  echo "Branch/ref: \`${GITHUB_REF_NAME:-local}\`"
  echo "Generated at: \`$(date -u '+%Y-%m-%dT%H:%M:%SZ')\`"
  echo
  echo "## Finding Counts"
  echo
  echo "| Tool | Exported finding count | Source artifact |"
  echo "| --- | ---: | --- |"
  echo "| Semgrep | ${SEMGREP_COUNT} | \`semgrep.sarif\` |"
  echo "| CodeQL | ${CODEQL_COUNT} | \`codeql-results/*.sarif\` |"
  echo "| SonarCloud | ${SONAR_COUNT} | \`sonar-issues.json\` |"
  echo
  echo "## Methodology"
  echo
  echo "- Semgrep is run with public/default-style rulesets only: \`p/security-audit\`, \`p/secrets\`, \`p/owasp-top-ten\`, and \`p/java\`."
  echo "- No project-specific Semgrep rules are used for this comparison."
  echo "- CodeQL is run with GitHub's Java/Kotlin analysis plus \`security-extended\` and \`security-and-quality\` query suites."
  echo "- SonarCloud results come from the configured SonarCloud project quality profile and exported security issues/hotspots."
  echo
  echo "## Expected Educational Vulnerabilities"
  echo
  echo "A Yes value means the tool exported at least one finding that references the file containing the intentionally vulnerable example. It does not guarantee the exact weakness classification is correct."
  echo
  echo "| Vulnerability scenario | File | Semgrep | CodeQL | SonarCloud |"
  echo "| --- | --- | --- | --- | --- |"
} > "${REPORT_FILE}"

write_case_row "Stored XSS via unsafe Thymeleaf rendering" "src/main/resources/templates/owners/ownerDetails.html"
write_case_row "Hardcoded fake secrets" "src/main/resources/application.properties"
write_case_row "Path traversal file download" "src/main/java/org/springframework/samples/petclinic/system/VulnerableFileDownloadController.java"
write_case_row "Missing admin authorization / business logic weakness" "src/main/java/org/springframework/samples/petclinic/system/VulnerableAdminReportController.java"
write_case_row "Sensitive data and user input in logs" "src/main/java/org/springframework/samples/petclinic/system/VulnerableLoggingController.java"
write_case_row "JPQL injection through string concatenation" "src/main/java/org/springframework/samples/petclinic/owner/VulnerableOwnerSearchController.java"

{
  echo
  echo "## Notes"
  echo
  echo "- Authorization/business-logic weaknesses are often underdetected by source-to-sink SAST rules unless custom rules model the expected role policy."
  echo "- SonarCloud results depend on the configured project key and \`SONAR_TOKEN\`; if the token is unavailable, the SonarCloud count will be zero."
  echo "- Review the raw SARIF/JSON artifacts for rule ids, severities, and exact locations."
} >> "${REPORT_FILE}"
