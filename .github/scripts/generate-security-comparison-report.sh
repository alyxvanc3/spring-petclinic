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
        ] | any(. == $expected_file))
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
  sonar="$(detected "${SONAR_ALL_FILES}" "${file}")"

  printf '| %s | `%s` | %s | %s | %s |\n' "${title}" "${file}" "${semgrep}" "${codeql}" "${sonar}" >> "${REPORT_FILE}"
}

write_classified_case_row() {
  local title="$1"
  local vulnerability_class="$2"
  local file="$3"
  local semgrep codeql sonar

  semgrep="$(detected "${SEMGREP_FILES}" "${file}")"
  codeql="$(detected "${CODEQL_FILES}" "${file}")"
  sonar="$(detected "${SONAR_ALL_FILES}" "${file}")"

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

count_detected() {
  local files="$1"
  shift
  local count=0
  local expected_file

  for expected_file in "$@"; do
    if grep -Fq "${expected_file}" <<< "${files}"; then
      count=$((count + 1))
    fi
  done

  echo "${count}"
}

variation_count_for_files() {
  local count=0
  local expected_file semgrep codeql sonar

  for expected_file in "$@"; do
    semgrep="$(detected "${SEMGREP_FILES}" "${expected_file}")"
    codeql="$(detected "${CODEQL_FILES}" "${expected_file}")"
    sonar="$(detected "${SONAR_ALL_FILES}" "${expected_file}")"
    if [[ "${semgrep}" != "${codeql}" || "${semgrep}" != "${sonar}" ]]; then
      count=$((count + 1))
    fi
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

STRUCTURAL_DETECTIONS=$(( \
  $(count_detected "${SEMGREP_FILES}" "${STRUCTURAL_FILES[@]}") + \
  $(count_detected "${CODEQL_FILES}" "${STRUCTURAL_FILES[@]}") + \
  $(count_detected "${SONAR_ALL_FILES}" "${STRUCTURAL_FILES[@]}") \
))
CONTEXTUAL_DETECTIONS=$(( \
  $(count_detected "${SEMGREP_FILES}" "${CONTEXTUAL_FILES[@]}") + \
  $(count_detected "${CODEQL_FILES}" "${CONTEXTUAL_FILES[@]}") + \
  $(count_detected "${SONAR_ALL_FILES}" "${CONTEXTUAL_FILES[@]}") \
))
STRUCTURAL_OPPORTUNITIES=$((${#STRUCTURAL_FILES[@]} * 3))
CONTEXTUAL_OPPORTUNITIES=$((${#CONTEXTUAL_FILES[@]} * 3))
VARIATION_CASES="$(variation_count_for_files "${ALL_EXPECTED_FILES[@]}")"

if (( STRUCTURAL_DETECTIONS > CONTEXTUAL_DETECTIONS )); then
  H1_RESULT="Supported in the current artifacts: structural cases have more tool-file detections than contextual cases."
elif (( STRUCTURAL_DETECTIONS == 0 && CONTEXTUAL_DETECTIONS == 0 )); then
  H1_RESULT="Not supported by the current artifacts: no structural or contextual target cases were detected, so no performance advantage can be established."
else
  H1_RESULT="Not supported by the current artifacts: structural cases do not show a detection advantage over contextual cases."
fi

if (( VARIATION_CASES > 0 )); then
  H4_RESULT="Supported in the current artifacts: at least one vulnerable file has differing detection outcomes across tools."
else
  H4_RESULT="Not supported by the current artifacts: all tools produced the same file-level outcome for every target case."
fi

{
  echo "# Academic Comparative Analysis of SAST Tool Results"
  echo
  echo "Commit: \`${GITHUB_SHA:-local}\`"
  echo "Branch/ref: \`${GITHUB_REF_NAME:-local}\`"
  echo "Generated at: \`$(date -u '+%Y-%m-%dT%H:%M:%SZ')\`"
  echo
  echo "## Abstract"
  echo
  echo "This report compares Semgrep, CodeQL, and SonarCloud on the same intentionally vulnerable Spring Petclinic codebase. The comparison is organized around two research hypotheses and uses exported SARIF/JSON artifacts as the unit of evidence. Detection is measured at file level, meaning a tool is counted as detecting a scenario when it reports at least one finding in the file that contains the seeded vulnerability."
  echo
  echo "## Research Hypotheses"
  echo
  echo "- **H1:** Traditional SAST tools perform better in detecting structural vulnerabilities than contextual vulnerabilities."
  echo "- **H4:** Different SAST tools produce varying results on the same vulnerable codebase."
  echo
  echo "## Experimental Design"
  echo
  echo "| Dimension | Description |"
  echo "| --- | --- |"
  echo "| Subject system | Intentionally vulnerable Spring Petclinic codebase |"
  echo "| Compared tools | Semgrep, CodeQL, SonarCloud |"
  echo "| Evidence artifacts | \`semgrep.sarif\`, \`codeql-results/*.sarif\`, \`sonar-issues.json\`, \`sonar-hotspots.json\` |"
  echo "| Detection unit | File-level match against the file that contains the seeded vulnerability |"
  echo "| Interpretation constraint | A file-level match does not prove that the exact weakness was classified correctly |"
  echo
  echo "## Tool Configuration"
  echo
  echo "- Semgrep is run with public/default-style rulesets only: \`p/security-audit\`, \`p/secrets\`, \`p/owasp-top-ten\`, and \`p/java\`."
  echo "- No project-specific Semgrep rules are used for this comparison."
  echo "- CodeQL is run with GitHub's Java/Kotlin analysis plus \`security-extended\` and \`security-and-quality\` query suites."
  echo "- SonarCloud results come from the configured SonarCloud project quality profile."
  echo "- SonarCloud issues are exported from \`api/issues/search\` with the current branch or pull request context."
  echo "- SonarCloud security hotspots are exported separately from \`api/hotspots/search\` with the same branch or pull request context."
  echo
  echo "## Vulnerability Classification"
  echo
  echo "| Class | Operational definition | Seeded scenarios |"
  echo "| --- | --- | --- |"
  echo "| Structural | Vulnerabilities that can usually be identified through syntactic patterns, data-flow, source-to-sink relationships, or configuration inspection | Stored XSS, hardcoded secrets, path traversal, JPQL injection |"
  echo "| Contextual | Vulnerabilities that depend on application policy, business rules, intended authorization boundaries, or semantic interpretation of sensitive behavior | Missing admin authorization, sensitive data and user input in logs |"
  echo
  echo "## Aggregate Finding Counts"
  echo
  echo "| Tool | Exported finding count | Source artifact |"
  echo "| --- | ---: | --- |"
  echo "| Semgrep | ${SEMGREP_COUNT} | \`semgrep.sarif\` |"
  echo "| CodeQL | ${CODEQL_COUNT} | \`codeql-results/*.sarif\` |"
  echo "| SonarCloud | ${SONAR_COUNT} issues / ${SONAR_HOTSPOT_COUNT} hotspots | \`sonar-issues.json\`, \`sonar-hotspots.json\` |"
  echo
  echo "## Vulnerability-Level Detection Matrix"
  echo
  echo "A Yes value means the tool exported at least one finding that references the file containing the intentionally vulnerable example. It does not guarantee the exact weakness classification is correct."
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
  echo "This table shows up to three findings per tool for each target file. A finding in the same file does not necessarily mean the expected weakness was classified correctly."
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

{
  echo
  echo "## Hypothesis Evaluation"
  echo
  echo "| Hypothesis | Evidence summary | Interpretation |"
  echo "| --- | --- | --- |"
  echo "| H1 | Structural detections: ${STRUCTURAL_DETECTIONS}/${STRUCTURAL_OPPORTUNITIES} tool-file opportunities; contextual detections: ${CONTEXTUAL_DETECTIONS}/${CONTEXTUAL_OPPORTUNITIES} tool-file opportunities | ${H1_RESULT} |"
  echo "| H4 | ${VARIATION_CASES}/${#ALL_EXPECTED_FILES[@]} target files show different Yes/No outcomes across Semgrep, CodeQL, and SonarCloud | ${H4_RESULT} |"
  echo
  echo "## Discussion"
  echo
  echo "The current comparison does not use custom rules or manual triage labels. Therefore, the results should be interpreted as tool output under the configured default rule sets, not as a complete measurement of exploitability or vulnerability presence. Contextual weaknesses, especially authorization and business-logic issues, remain difficult for general-purpose SAST because the expected access policy is rarely explicit in the source code."
  echo
  echo "## Validity Threats"
  echo
  echo "- **Construct validity:** File-level detection may overestimate true detection when the reported rule is unrelated to the seeded weakness."
  echo "- **Internal validity:** Missing or empty SARIF/JSON artifacts produce zero counts even if a tool would detect the issue under a complete run."
  echo "- **External validity:** Results from one Spring Petclinic variant may not generalize to other frameworks, rule configurations, or vulnerability corpora."
  echo "- **Configuration validity:** SonarCloud results depend on the configured project key and \`SONAR_TOKEN\`; if the token is unavailable, the SonarCloud count will be zero."
  echo
  echo "## Conclusion"
  echo
  echo "Based on the exported artifacts for this run, the report provides a structured comparison framework for H1 and H4 but does not establish support for a structural-over-contextual advantage or inter-tool variation unless such differences appear in the generated detection matrix. Raw SARIF and JSON artifacts should be reviewed for rule identifiers, severities, and exact locations before drawing final academic conclusions."
} >> "${REPORT_FILE}"
