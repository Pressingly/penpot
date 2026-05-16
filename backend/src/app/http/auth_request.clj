;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/.
;;
;; Copyright (c) KALEIDOS INC

(ns app.http.auth-request
  "Middleware that trusts X-Auth-Request-* headers set by a forward-auth
  proxy (e.g. oauth2-proxy, Authelia, Traefik ForwardAuth).

  Enabled via PENPOT_FLAGS: enable-x-auth-request-headers (parsed as :x-auth-request-headers).
  Any request carrying an X-Auth-Request-Email header is treated as pre-authenticated.
  A Penpot session cookie is created on the response so that the browser
  does not need to visit the login screen.

  Optional: enable-x-auth-request-auto-register (parsed as :x-auth-request-auto-register)
  automatically creates a Penpot profile (with a default team) for email addresses
  that are not yet registered."
  (:require
   [app.common.logging :as l]
   [app.config :as cf]
   [app.db :as db]
   [app.http :as-alias http]
   [app.http.access-token :as-alias actoken]
   [app.http.session :as session]
   [app.rpc.commands.auth :as auth]
   [app.rpc.commands.profile :as profile]
   [cuerdas.core :as str]
   [yetti.request :as yreq]
   [yetti.response :as yres]))

(set! *warn-on-reflection* true)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; HELPERS
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- valid-email?
  [s]
  (boolean (re-matches #"[^\s@]+@[^\s@]+\.[^\s@]+" s)))

(defn- resolve-email
  "If the claim is already a valid email, return it as-is.
  Otherwise treat it as a bare username and append @<default-email-domain>."
  [email-claim]
  (if (valid-email? email-claim)
    email-claim
    (let [domain (or (cf/get :default-email-domain) "askii.ai")]
      (l/wrn :hint "x-auth-request: email claim is not a valid address, constructing from default-email-domain"
             :claim email-claim
             :domain domain)
      (str (first (str/split email-claim #"@")) "@" domain))))

(defn- get-or-register-profile
  "Looks up a profile by email. If not found and the
  :x-auth-request-auto-register flag is enabled, creates a new active
  profile with a default team. Returns nil when the profile does not
  exist and auto-registration is disabled."
  [cfg email fullname]
  (db/tx-run! cfg
              (fn [{:keys [::db/conn] :as cfg}]
                (or (profile/get-profile-by-email conn email)
                    (when (contains? cf/flags :x-auth-request-auto-register)
                      (let [display-name (or (not-empty fullname)
                                             (first (str/split email #"@")))
                            profile      (auth/create-profile cfg
                                                              {:email    email
                                                               :fullname display-name
                                                               :backend  "x-auth-request"
                                                               :is-active true})]
                        (l/inf :hint "x-auth-request: auto-registered profile"
                               :email email
                               :profile-id (str (:id profile)))
                        (auth/create-profile-rels conn profile)))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; MIDDLEWARE
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; The profile-lookup try/catch (below) narrows what counts as
;; "transient" to known DB/IO failure classes — Postgres exceptions,
;; JDBC SQL exceptions, JDBC connection exceptions, java.io.IOException.
;; A broader `catch Throwable` would also swallow validation errors,
;; bad-input parses, and programming bugs, masking them as transient
;; failures that silently extend a stale session. On transient
;; failure we preserve whatever wrap-session decided and pass through
;; unchanged — graceful degradation, but only for the failure modes
;; that genuinely warrant it. Any other exception escapes the catch
;; and surfaces through the standard error handler as a 500.

(def ^:private transient-exception-classes
  #{java.sql.SQLException
    java.sql.SQLTransientException
    java.sql.SQLNonTransientConnectionException
    java.io.IOException
    org.postgresql.util.PSQLException})

(defn- transient-exception?
  "True iff cause (or any cause-chain ancestor) is an instance of a
  class we treat as transient. Walks the cause chain so a wrapped
  ExecutionException with a SQLException root still classifies."
  [cause]
  (loop [ex cause]
    (cond
      (nil? ex)                                              false
      (some #(instance? % ex) transient-exception-classes)   true
      :else                                                  (recur (.getCause ^Throwable ex)))))

(defn- clear-stale-session
  "Returns a request with the local-session keys AND ::http/auth-data
  removed. Both must be cleared together because downstream handlers
  read identity from BOTH `::session/profile-id` (the post-wrap-authz
  shorthand) and `::http/auth-data.claims.uid` (used by errors.clj for
  log enrichment on cookie-auth requests). Leaving auth-data in place
  after re-keying or after a mismatch flush leaks the stale identity
  to that reader.

  (access_token.clj reads ::http/auth-data too, but only branches on
  `:type :token` — the API-key path is short-circuited before we get
  here, so it's not relevant to the cookie-auth flow this middleware
  reconciles.)"
  [request]
  (dissoc request
          ::session/profile-id
          ::session/session
          ::http/auth-data))

(defn- response-has-auth-cookie?
  "True when the handler already wrote the auth-token cookie on the
  response. Used to avoid clobbering an explicit logout / re-issue
  written by a downstream handler with a fresh re-key cookie. Same
  guard shape as session.clj's renewal path."
  [response]
  (contains? (::yres/cookies response)
             (cf/get :auth-token-cookie-name)))

(defn- wrap-authz
  [handler cfg]
  (fn [request]
    (let [atoken-pid  (::actoken/profile-id request)
          session-pid (::session/profile-id request)
          email-claim (yreq/get-header request "x-auth-request-email")]
      (cond
        ;; Access-token (API key) — programmatic identity issued out-of-band
        ;; by the user. Not a browser SSO session, so the header is not
        ;; meaningful here. Pass through unconditionally.
        (some? atoken-pid)
        (handler request)

        ;; No proxy header — trust whatever wrap-session decided (session
        ;; cookie, or anonymous). Without a header we have no upstream
        ;; identity to compare against.
        (str/blank? email-claim)
        (handler request)

        :else
        (let [local-part    (first (str/split email-claim #"@"))
              email         (resolve-email email-claim)
              fullname      (or (not-empty (yreq/get-header request "x-auth-request-user"))
                                local-part)
              profile-state (try
                              {:status :ok
                               :profile (get-or-register-profile cfg email fullname)}
                              (catch Throwable cause
                                (if (transient-exception? cause)
                                  (do
                                    (l/err :hint "x-auth-request: transient error resolving profile, preserving session"
                                           :email email
                                           :cause cause)
                                    {:status :error
                                     :cause cause})
                                  ;; Non-transient — programming bug, validation
                                  ;; failure, bad input. Rethrow so the standard
                                  ;; error pipeline returns 500 instead of
                                  ;; silently masking it as a "preserve session"
                                  ;; pass-through.
                                  (throw cause))))
              profile       (:profile profile-state)]
          (cond
            ;; Transient failure resolving the proxy identity. We have NO
            ;; basis to flush the existing session (a Postgres restart or
            ;; network blip would otherwise log everyone out), so preserve
            ;; whatever wrap-session decided. The next successful request
            ;; reconciles normally.
            (= :error (:status profile-state))
            (do
              (l/wrn :hint "x-auth-request: preserving local auth state because profile resolution failed"
                     :email email
                     :session-profile-id (some-> session-pid str))
              (handler request))

            (nil? profile)
            ;; Header email doesn't resolve to a profile (and auto-register
            ;; is off). The upstream identity is something the local DB
            ;; doesn't know — we cannot safely keep serving whatever session
            ;; cookie alice happens to have in this browser, because the
            ;; upstream says alice is no longer the active identity. Clear
            ;; the in-flight local session markers AND auth-data, then
            ;; expire the browser's auth-token cookie so subsequent
            ;; requests cannot resurrect the stale local session. The
            ;; request then continues unauthenticated (downstream handlers
            ;; will respond with 401/redirect-to-login per their own rules).
            (do
              (l/wrn :hint "x-auth-request: no profile found for email, clearing local session"
                     :email email
                     :session-profile-id (some-> session-pid str))
              (let [delete-session! (session/delete-fn cfg)
                    cleared         (clear-stale-session request)
                    response        (handler cleared)]
                ;; delete-fn reads ::id from the request — pass the
                ;; original (pre-clear) so the server-side row is
                ;; actually removed, not just the browser cookie.
                ;; Until the companion wrap-authz fix sets ::id, the
                ;; server-side delete is a no-op; this is still the
                ;; correct shape for when that lands.
                (delete-session! request response)))

            ;; Blocked / inactive incoming identity. Return 403 — and if
            ;; there was a session for a DIFFERENT user, flush it too. The
            ;; openspec Rule 2 contract (identity mismatch SHALL flush)
            ;; applies regardless of whether the new identity is usable;
            ;; otherwise alice's session survives an attempted switch to
            ;; the blocked user bob and the next request still serves alice.
            (or (:is-blocked profile)
                (not (:is-active profile)))
            (do
              (l/wrn :hint (if (:is-blocked profile)
                             "x-auth-request: profile is blocked, denying access"
                             "x-auth-request: profile is not active, denying access")
                     :email email
                     :profile-id (str (:id profile))
                     :session-profile-id (some-> session-pid str))
              (let [response {::yres/status 403}]
                (if (and session-pid (not= session-pid (:id profile)))
                  ;; Identity mismatch with a refused incoming user — also
                  ;; clear the existing local session cookie so alice
                  ;; doesn't keep her session via the still-valid
                  ;; auth-token cookie on her browser.
                  (let [delete-session! (session/delete-fn cfg)]
                    (delete-session! request response))
                  response)))

            ;; Existing browser session matches the proxy-asserted identity.
            ;; Steady-state case — no work to do.
            (and session-pid (= session-pid (:id profile)))
            (handler request)

            ;; Either no existing session, or the session points at a
            ;; *different* profile than oauth2-proxy is asserting. Re-key.
            ;;
            ;; Re-keying is what fixes the stale-session bug after the
            ;; portal "log out of all apps" + new-user login pattern:
            ;; oauth2-proxy + Cognito are cleared, but Penpot's own
            ;; auth-token cookie on its subdomain survives. Without this
            ;; branch, wrap-session would resolve the old session-pid and
            ;; this middleware (under the previous always-skip-when-session
            ;; rule) would never override it.
            :else
            (do
              (when session-pid
                (l/inf :hint "x-auth-request: proxy identity differs from existing session — re-keying"
                       :session-profile-id (str session-pid)
                       :header-profile-id  (str (:id profile))))
              (l/dbg :hint "x-auth-request: authenticating via forwarded header"
                     :email email
                     :profile-id (str (:id profile)))
              (let [create-session! (session/create-fn cfg profile)
                    response        (-> request
                                        clear-stale-session
                                        (assoc ::session/profile-id (:id profile))
                                        handler)]
                ;; Issue a fresh auth-token cookie unless the downstream
                ;; handler already wrote the auth-token cookie on the
                ;; response (e.g. an explicit logout that called
                ;; clear-session-cookie, or an auth endpoint that re-issued
                ;; the cookie itself). Otherwise the re-key would clobber
                ;; the handler's intent — most visibly, it would prevent a
                ;; user from ever completing a logout while the SSO
                ;; cookie is still present.
                (if (response-has-auth-cookie? response)
                  response
                  (create-session! request response))))))))))

(def authz
  {:name ::authz
   :compile (fn [& _]
              (when (contains? cf/flags :x-auth-request-headers)
                wrap-authz))})
