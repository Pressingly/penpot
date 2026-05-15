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
        (let [local-part (first (str/split email-claim #"@"))
              email      (resolve-email email-claim)
              fullname   (or (not-empty (yreq/get-header request "x-auth-request-user"))
                             local-part)
              profile    (try
                           (get-or-register-profile cfg email fullname)
                           (catch Throwable cause
                             (l/err :hint "x-auth-request: error resolving profile"
                                    :email email
                                    :cause cause)
                             nil))]
          (cond
            (nil? profile)
            ;; Header email doesn't resolve to a profile (and auto-register
            ;; is off). The upstream identity is something the local DB
            ;; doesn't know — we cannot safely keep serving whatever session
            ;; cookie alice happens to have in this browser, because the
            ;; upstream says alice is no longer the active identity. Clear
            ;; the in-flight local session markers and expire the browser's
            ;; auth-token cookie so subsequent requests cannot resurrect the
            ;; stale local session. The request then continues
            ;; unauthenticated (downstream handlers will respond with
            ;; 401/redirect-to-login per their own rules).
            (do
              (l/wrn :hint "x-auth-request: no profile found for email, clearing local session"
                     :email email
                     :session-profile-id (some-> session-pid str))
              (let [delete-session! (session/delete-fn cfg)
                    request         (dissoc request
                                            ::session/profile-id
                                            ::session/session-id
                                            ::session/session)
                    response        (handler request)]
                (delete-session! request response)))

            (:is-blocked profile)
            (do
              (l/wrn :hint "x-auth-request: profile is blocked, denying access"
                     :email email
                     :profile-id (str (:id profile)))
              {::yres/status 403})

            (not (:is-active profile))
            (do
              (l/wrn :hint "x-auth-request: profile is not active, denying access"
                     :email email
                     :profile-id (str (:id profile)))
              {::yres/status 403})

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
                                        (dissoc ::session/session-id
                                                ::session/session)
                                        (assoc ::session/profile-id (:id profile))
                                        handler)]
                ;; Issue a fresh auth-token cookie; replaces the stale one
                ;; the browser still has (if any).
                (create-session! request response)))))))))

(def authz
  {:name ::authz
   :compile (fn [& _]
              (when (contains? cf/flags :x-auth-request-headers)
                wrap-authz))})
