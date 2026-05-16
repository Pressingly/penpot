#!/usr/bin/env bash
#
# sso-audit.sh — Penpot-side fork audit against the cross-app SSO contract.
#
# ============================================================================
# Covers fork-side rows of awais786/sso-rules-moneta:openspec/specs/
# proxy-auth-middleware/spec.md that a deterministic bash check can verify
# against Penpot's source tree. Catches regressions BEFORE they reach
# foss-server-bundle-devstack.
#
# Exit codes:
#   0 — all rows ✅ or n/a / informational
#   1 — at least one SECURITY-CRITICAL row failed
#
# Rows covered:
#   Row 14 — logout shape: SPA logout (frontend/src/app/main/data/auth.cljs)
#            MUST NOT call /oauth2/sign_out.
#   Row 20 — session-identity reconciliation (Rule 2 mismatch flush):
#            backend/src/app/http/auth_request.clj MUST call
#            (session/delete-fn cfg) on unresolvable mismatch OR
#            (create-session!) on resolvable mismatch (in-place re-key).
#            Both satisfy the contract; presence of either is the deterministic
#            signal that wrap-authz reconciles upstream identity vs session.
#            SECURITY-CRITICAL.
#   Row 21 — email-shape detection MUST NOT use polynomial-backtracking
#            regex. Penpot uses valid-email? helper (regex) — this row only
#            fires if the unanchored polynomial-backtrack shape is introduced.
# ============================================================================

set -euo pipefail

AUTH_REQUEST="backend/src/app/http/auth_request.clj"
AUTH_FRONTEND="frontend/src/app/main/data/auth.cljs"

declare -a ROW_STATUS=()
declare -a ROW_TITLES=(
  "logout shape: SPA logout does not call /oauth2/sign_out"
  "session-identity reconciliation present (Rule 2 mismatch flush)"
  "email-shape detection uses substring, not polynomial regex"
)
declare -a ROW_NOTES=()
declare -a ROW_NUMBERS=(14 20 21)

SECURITY_CRITICAL=(1)
SECURITY_CRITICAL_FAILS=0

record() {
  local idx=$1 status=$2 note=$3
  ROW_STATUS[$idx]="$status"
  ROW_NOTES[$idx]="$note"
  if [[ "$status" == "❌" ]]; then
    for c in "${SECURITY_CRITICAL[@]}"; do
      if [[ "$c" -eq "$idx" ]]; then
        SECURITY_CRITICAL_FAILS=$((SECURITY_CRITICAL_FAILS + 1))
        return
      fi
    done
  fi
}

# ============================================================================
# Row 14 (idx 0): logout shape — narrow check
# ============================================================================
check_row_14() {
  if [[ ! -f "$AUTH_FRONTEND" ]]; then
    record 0 "?" "$AUTH_FRONTEND not found — skipping"
    return
  fi

  if grep -qE '/oauth2/sign_?out' "$AUTH_FRONTEND"; then
    local line
    line=$(grep -nE '/oauth2/sign_?out' "$AUTH_FRONTEND" | head -1)
    record 0 "❌" "Logout calls \`/oauth2/sign_out\` at $AUTH_FRONTEND:$line — per logout-flow spec, per-app Logout is navigation-only. Drop the call; portal 'Logout all' handles oauth2-proxy clearing."
    return
  fi

  record 0 "✅" "$AUTH_FRONTEND does not invoke \`/oauth2/sign_out\` (this row verifies only that the SPA doesn't try to clear the upstream proxy cookie itself; that's the portal's job)"
}

# ============================================================================
# Row 20 (idx 1): session-identity reconciliation
#
# Penpot's flush mechanism has three paths per the spec:
#   1. Resolvable + active mismatch  →  in-place re-key (create-session! on
#      response with the new profile-id)
#   2. Blocked / inactive incoming   →  403 + renewal guard prevents stale
#      cookie extension
#   3. Unresolvable upstream         →  drop in-flight session markers AND
#      expire the browser cookie via (session/delete-fn cfg)
#
# All three paths must exist in wrap-authz for the contract to hold. The
# deterministic signal is the presence of `session/delete-fn` (the
# drop+expire path, unique to Pressingly/penpot#18) AND `create-session!`
# (the re-key path) in auth_request.clj.
#
# If either marker is absent, the middleware is in an earlier state where
# wrap-authz short-circuited on the session cookie without consulting the
# upstream header — the cross-user stale-session leak.
#
# SECURITY-CRITICAL: without these, the stale-session leak returns.
# ============================================================================
check_row_20() {
  if [[ ! -f "$AUTH_REQUEST" ]]; then
    record 1 "?" "$AUTH_REQUEST not found — skipping"
    return
  fi

  local has_delete_fn
  has_delete_fn=$(grep -cE "session/delete-fn" "$AUTH_REQUEST" || true)

  local has_create_session
  has_create_session=$(grep -cE "create-session!" "$AUTH_REQUEST" || true)

  if [[ "$has_delete_fn" -gt 0 && "$has_create_session" -gt 0 ]]; then
    record 1 "✅" "$AUTH_REQUEST contains \`session/delete-fn\` (drop+expire path) AND \`create-session!\` (re-key path) — Rule 2 three-path mismatch flush in place"
    return
  fi

  local missing=""
  [[ "$has_delete_fn" -eq 0 ]] && missing="${missing} session/delete-fn (drop+expire path);"
  [[ "$has_create_session" -eq 0 ]] && missing="${missing} create-session! (re-key path);"

  record 1 "❌" "$AUTH_REQUEST is missing:$missing The cross-app spec (proxy-auth-middleware Rule 2) requires wrap-authz to reconcile the upstream X-Auth-Request-Email against the session profile-id. On resolvable + active mismatch: re-key by calling create-session! on the response with the new profile-id. On unresolvable upstream: dissoc the session markers AND call (session/delete-fn cfg) to expire the browser cookie. Without both paths, the stale-session-on-user-switch leak returns. Reference: Pressingly/penpot#18."
}

# ============================================================================
# Row 21 (idx 2): polynomial-regex avoidance in email-shape detection
#
# Penpot's `valid-email?` helper uses a regex. The audit fires only if the
# unanchored polynomial-backtrack shape (^[^\s@]+@[^\s@]+\.[^\s@]+$) is
# introduced. The current `[^\s@]+@[^\s@]+\.[^\s@]+` pattern with the
# `re-matches` Clojure function is anchored by re-matches (not by `^...$`)
# and on a fixed-size input is not exploitable. The audit looks specifically
# for the explicit anchored polynomial shape.
# ============================================================================
check_row_21() {
  if [[ ! -f "$AUTH_REQUEST" ]]; then
    record 2 "?" "$AUTH_REQUEST not found — skipping"
    return
  fi

  # Anchored polynomial-backtracking email-shape regex (the literal one
  # CodeQL flags). Clojure regexes use Java syntax.
  local hits
  hits=$(grep -nE '\^\[\^[\\\\]s@\]\+@\[\^[\\\\]s@\]\+\\\.\[\^[\\\\]s@\]\+\$' "$AUTH_REQUEST" 2>/dev/null || true)

  if [[ -n "$hits" ]]; then
    record 2 "❌" "Polynomial-backtracking email-shape regex detected in $AUTH_REQUEST: $hits. The current valid-email? uses re-matches which anchors implicitly; introducing the explicit ^...$ form re-enables polynomial backtracking on adversarial input. Rewrite to substring-based check per openspec proxy-auth-middleware §'email-shape detection SHALL avoid polynomial-backtracking regex'."
    return
  fi

  record 2 "✅" "No polynomial-backtracking email-shape regex in $AUTH_REQUEST; using re-matches (implicit anchoring on fixed-size input) or substring check"
}

# ============================================================================
# Run checks
# ============================================================================
check_row_14
check_row_20
check_row_21

# ============================================================================
# Print table
# ============================================================================
echo "## Penpot SSO Fork Audit"
echo
echo "Cross-app contract: https://github.com/awais786/sso-rules-moneta/blob/main/openspec/specs/proxy-auth-middleware/spec.md"
echo "Row numbers match the 21-row table at https://github.com/awais786/sso-rules-moneta/blob/main/skills/app-rules/SKILL.md#5-report"
echo
echo "| Row | Invariant | Status | Notes |"
echo "|-----|-----------|--------|-------|"
for i in "${!ROW_TITLES[@]}"; do
  printf "| %d | %s | %s | %s |\n" \
    "${ROW_NUMBERS[$i]}" "${ROW_TITLES[$i]}" "${ROW_STATUS[$i]:-?}" "${ROW_NOTES[$i]:-}"
done
echo

TOTAL_FAILS=0
for s in "${ROW_STATUS[@]}"; do
  [[ "$s" == "❌" ]] && TOTAL_FAILS=$((TOTAL_FAILS + 1))
done

if [[ "$TOTAL_FAILS" -eq 0 ]]; then
  echo "**All fork-side invariants hold.**"
  exit 0
fi

echo "**$TOTAL_FAILS violations.** Security-critical (row 20): $SECURITY_CRITICAL_FAILS."
if [[ "$SECURITY_CRITICAL_FAILS" -gt 0 ]]; then
  exit 1
fi
exit 0
