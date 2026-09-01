#!/usr/bin/env bash
# Verify the write guardrail actually blocks what it claims to block.
#
# Run this before you trust the harness with a production tenant, and again
# after you upgrade falcon-mcp. A security control you have not tested is a
# security control you do not have.
#
#   ./scripts/test-guardrail.sh

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

HOOK=".claude/hooks/guard-falcon-writes.py"
pass=0
fail=0

decide() {
  # Prints ALLOW or DENY for a given tool name. Reads permissionDecision rather
  # than treating any output as a denial -- the hook now also speaks on allow,
  # when it clamps a limit.
  local out
  out=$(printf '{"tool_name":"%s"}' "$1" | python3 "$HOOK" 2>/dev/null)
  if [ -z "$out" ]; then echo "ALLOW"; return; fi
  printf '%s' "$out" | python3 -c \
    'import json,sys; print(json.load(sys.stdin)["hookSpecificOutput"]["permissionDecision"].upper())' \
    2>/dev/null || echo "MALFORMED"
}

limit_of() {
  # Prints the limit the hook would let through for a requested limit, or the
  # literal string "unchanged" when the hook stays silent.
  local requested="$1" out
  out=$(printf '{"tool_name":"mcp__falcon-mcp__falcon_search_detections","tool_input":{"filter":"status:%s","limit":%s}}' \
        "'new'" "$requested" | python3 "$HOOK" 2>/dev/null)
  if [ -z "$out" ]; then echo "unchanged"; return; fi
  printf '%s' "$out" | python3 -c '
import json, sys
out = json.load(sys.stdin)["hookSpecificOutput"]
updated = out.get("updatedInput")
if updated is None:
    print("unchanged")
else:
    # The filter must survive: updatedInput replaces the whole object, so a
    # rewrite that drops a sibling key silently changes the query.
    print(updated["limit"] if updated.get("filter") == "status:'"'"'new'"'"'"
          else "DROPPED-FILTER")
' 2>/dev/null || echo "MALFORMED"
}

expect_limit() {
  local requested="$1" want="$2" got
  got=$(limit_of "$requested")
  if [ "$got" = "$want" ]; then
    pass=$((pass + 1))
  else
    printf '  FAIL  limit=%-36s got %s, wanted %s\n' "$requested" "$got" "$want"
    fail=$((fail + 1))
  fi
}

expect() {
  local tool="mcp__falcon-mcp__$1" want="$2" got
  got=$(decide "$tool")
  if [ "$got" = "$want" ]; then
    pass=$((pass + 1))
  else
    printf '  FAIL  %-42s got %s, wanted %s\n' "$1" "$got" "$want"
    fail=$((fail + 1))
  fi
}

echo "Falcon MCP harness -- guardrail tests"
echo

# --- Read-only tools must pass through --------------------------------------
# falcon_count_kubernetes_containers and falcon_download_report_execution are
# the important ones here: naive substring matching on "contain" and "execute"
# wrongly blocks both. They are regression tests, not filler.
#
# The aggregate_/preview_ entries are also regressions: all of them carry
# readOnlyHint=True in falcon-mcp 0.17.0 and were being refused before those
# two verbs were added to READ_VERBS.
echo "Read-only tools (expect ALLOW):"
for tool in \
  falcon_search_detections \
  falcon_search_vulnerabilities \
  falcon_search_hosts \
  falcon_search_kubernetes_containers \
  falcon_count_kubernetes_containers \
  falcon_get_host_details \
  falcon_get_detection_details \
  falcon_list_enabled_modules \
  falcon_list_enabled_tools \
  falcon_check_connectivity \
  falcon_idp_investigate_entity \
  falcon_download_report_execution \
  falcon_search_iocs \
  falcon_search_firewall_rules \
  falcon_aggregate_detections \
  falcon_aggregate_rtr_sessions \
  falcon_preview_quarantine_actions \
  falcon_preview_recon_rule; do
  expect "$tool" ALLOW
done

# --- Tools that read like queries but are writes -----------------------------
# falcon_search_cases is POST-based and flagged readOnlyHint=False upstream.
# The verb allowlist would wave it through on the name alone.
echo "Misleadingly named writes (expect DENY):"
expect falcon_search_cases DENY

# --- Write tools must be denied in the default posture -----------------------
# Names verified against falcon-mcp 0.17.0: add_ioc is singular, remove_iocs is
# plural, and there is no falcon_add_iocs.
echo "Write tools, default read-only posture (expect DENY):"
for tool in \
  falcon_add_ioc \
  falcon_create_policy \
  falcon_update_policy \
  falcon_perform_policy_action \
  falcon_set_policy_precedence \
  falcon_update_detections \
  falcon_manage_host_grouping_tags \
  falcon_create_cspm_suppression_rule \
  falcon_launch_scheduled_report; do
  expect "$tool" DENY
done

# --- Destructive tools must be denied unconditionally ------------------------
echo "Destructive tools (expect DENY):"
for tool in \
  falcon_remove_iocs \
  falcon_delete_policies \
  falcon_delete_quarantined_files \
  falcon_delete_cspm_suppression_rules \
  falcon_delete_rtr_session \
  falcon_execute_rtr_read_only_command \
  falcon_run_rtr_read_only_command_and_wait \
  falcon_contain_host \
  falcon_lift_containment \
  falcon_quarantine_file \
  falcon_rtr_execute_command; do
  expect "$tool" DENY
done

# --- Non-Falcon tools are none of this hook's business -----------------------
echo "Unrelated tools (expect ALLOW -- this hook only governs Falcon):"
for raw in Bash Read mcp__some_other_server__do_thing; do
  got=$(decide "$raw")
  if [ "$got" = "ALLOW" ]; then
    pass=$((pass + 1))
  else
    printf '  FAIL  %-42s got %s, wanted ALLOW\n' "$raw" "$got"
    fail=$((fail + 1))
  fi
done

# --- The limit ceiling -------------------------------------------------------
# Context discipline as an enforced boundary rather than a request. A read tool
# is still ALLOWed; only the parameter changes.
#
# Clamping is off unless HARNESS_MAX_LIMIT is set, so the ceiling cases below
# set it explicitly. Testing them against the default would only re-test the
# default.
echo "Clamping is off by default:"
expect_limit 500 unchanged
expect_limit 26 unchanged

echo "Limit clamping with HARNESS_MAX_LIMIT=25:"
export HARNESS_MAX_LIMIT=25
expect_limit 500 25          # the case this exists for
expect_limit 26 25           # one over
expect_limit 25 unchanged    # exactly at the ceiling: no rewrite, no chatter
expect_limit 10 unchanged    # the recommended value is left alone
expect_limit 0 unchanged     # already minimal
expect_limit '"500"' unchanged   # a string is not a limit; pass it through
expect_limit true unchanged      # a bool is an int in Python -- must not clamp
expect_limit null unchanged      # absent means server default
unset HARNESS_MAX_LIMIT

echo "Limit ceiling raised by HARNESS_MAX_LIMIT=400:"
export HARNESS_MAX_LIMIT=400
expect_limit 500 400
expect_limit 300 unchanged
unset HARNESS_MAX_LIMIT

echo "A malformed HARNESS_MAX_LIMIT falls back to the default, not to no ceiling:"
export HARNESS_MAX_LIMIT=lots
expect_limit 500 unchanged
unset HARNESS_MAX_LIMIT

# --- The opt-in unlock must open writes but NOT destructive ops --------------
echo "With HARNESS_ALLOW_WRITES=true:"
export HARNESS_ALLOW_WRITES=true
expect falcon_create_policy ALLOW      # writes unlocked on purpose
expect falcon_update_detections ALLOW
expect falcon_delete_policies DENY     # still blocked -- unconditional
expect falcon_contain_host DENY
unset HARNESS_ALLOW_WRITES

echo
if [ "$fail" -eq 0 ]; then
  echo "PASS -- $pass checks, 0 failures."
  exit 0
fi
echo "FAIL -- $fail of $((pass + fail)) checks failed. Do not use this harness"
echo "against a production tenant until the guardrail passes."
exit 1
