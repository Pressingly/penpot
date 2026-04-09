;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/.
;;
;; Copyright (c) Pressingly / foss-server-bundle

(ns app.http.proxy-auth
  "mPass SSO proxy-auth HTTP route.

  Used when penpot runs behind Traefik + oauth2-proxy ForwardAuth. By
  the time a request reaches this route, oauth2-proxy has already
  validated the Cognito session and injected `X-Auth-Request-Email` /
  `X-Auth-Request-User` headers.

  On GET /api/auth/proxy-login:
    1. Read `x-auth-request-email` header.
    2. Look up the profile by email; if missing, create it via
       auth/create-profile + auth/create-profile-rels (same path used
       by the LDAP login flow).
    3. Use session/create-fn to insert an http_session_v2 row and
       attach the auth-token cookie to the response.
    4. 302-redirect to `/` so the frontend reloads with the new cookie
       and the regular session machinery takes over.

  Frontend contract: on first visit (no auth-token cookie), the penpot
  frontend should navigate to `/api/auth/proxy-login` instead of the
  native login screen. See docs/mpass-sso-rollout.md.

  Only uses PUBLIC penpot APIs so it is safe across penpot upgrades."
  (:require
   [app.common.exceptions :as ex]
   [app.common.logging :as l]
   [app.common.schema :as sm]
   [app.config :as cf]
   [app.db :as db]
   [app.http.session :as session]
   [app.rpc.commands.auth :as auth]
   [app.rpc.commands.profile :as profile]
   [app.setup :as-alias setup]
   [cuerdas.core :as str]
   [integrant.core :as ig]
   [yetti.request :as yreq]
   [yetti.response :as yres]))

(defn- redirect-response
  [uri]
  {::yres/status 302
   ::yres/headers {"location" (str uri)}})

(defn- read-email
  "Read and normalize the email from the oauth2-proxy forwarded header."
  [request]
  (some-> (yreq/get-header request "x-auth-request-email")
          str/trim
          str/lower
          (as-> s (when-not (str/empty? s) s))))

(defn- read-fullname
  "Derive a default fullname from the email local-part. Cognito does
  not forward a `name` header by default; users can edit this later."
  [email]
  (let [local (first (str/split email #"@" 2))]
    (if (str/empty? local) email local)))

(defn- login-or-register
  "Look up or create a penpot profile for the given email. Mirrors
  rpc.commands.ldap/login-or-register — same helpers, same defaults.
  Runs in a DB transaction so the profile + team-relations are created
  atomically."
  [cfg email]
  (db/tx-run!
   cfg
   (fn [{:keys [::db/conn] :as cfg}]
     (or (some->> email
                  (profile/clean-email)
                  (profile/get-profile-by-email conn))
         (->> {:email email
               :fullname (read-fullname email)
               :is-active true
               :is-demo false
               :backend "mpass"}
              (auth/create-profile cfg)
              (auth/create-profile-rels cfg)
              (profile/strip-private-attrs))))))

(defn- proxy-login-handler
  [cfg request]
  (let [email (read-email request)]
    (if (nil? email)
      (do
        (l/warn :hint "proxy-login called without x-auth-request-email header")
        (ex/raise :type :authentication
                  :code :proxy-header-missing
                  :hint "x-auth-request-email header is required"))

      (let [profile (login-or-register cfg email)]
        (when (:is-blocked profile)
          (ex/raise :type :restriction
                    :code :profile-blocked
                    :hint "profile is blocked"))

        (l/debug :hint "proxy-login establishing session"
                 :email email
                 :profile-id (str (:id profile)))

        ;; Apply session/create-fn as a response transformer — it
        ;; inserts the http_session_v2 row and attaches the auth-token
        ;; cookie. Then 302 to `/` so the frontend reloads and picks
        ;; up the cookie via its normal auth-check flow.
        (let [sxf (session/create-fn cfg profile)]
          (->> (redirect-response "/")
               (sxf request)))))))

(def ^:private schema:routes-params
  [:map
   ::session/manager
   ::setup/props
   ::db/pool])

(defmethod ig/assert-key ::routes
  [_ params]
  (assert (sm/check schema:routes-params params)))

(defmethod ig/init-key ::routes
  [_ cfg]
  ;; Gate on :x-auth-request-headers flag (penpot strips the `enable-`
  ;; prefix at parse time) so this route is only reachable when the
  ;; deployment has explicitly opted into proxy auth. When the flag is
  ;; absent the route still exists but returns 404.
  (if (contains? cf/flags :x-auth-request-headers)
    ["/api/auth/proxy-login"
     {:handler (partial proxy-login-handler cfg)
      :allowed-methods #{:get}}]
    ["/api/auth/proxy-login"
     {:handler (fn [_] {::yres/status 404})
      :allowed-methods #{:get}}]))
