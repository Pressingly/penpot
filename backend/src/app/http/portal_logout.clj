;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/.
;;
;; Copyright (c) KALEIDOS INC

(ns app.http.portal-logout
  "GET /api/auth/portal-logout — cross-origin redirect-chain entry point
  for the foss-server-bundle portal's \"Log out of all apps\" flow.

  Clears the auth-token cookie + invalidates the server-side session row
  via the same `session/delete-fn` primitive that `auth/logout` RPC uses.
  302s to ?next= if its host equals PLATFORM_DOMAIN or is a subdomain;
  otherwise returns 200 with cookies still cleared.

  CSRF-exempt by design: cross-origin redirect chains cannot share
  Penpot's CSRF token. Residual force-logout risk (`<img src=…>`) is
  acceptable — only the session itself is lost; the upstream Cognito
  session controls real access via oauth2-proxy ForwardAuth, which
  re-auths on the next request."
  (:require
   [app.config :as cf]
   [app.http.session :as session]
   [cuerdas.core :as str]
   [integrant.core :as ig]
   [yetti.response :as yres])
  (:import
   (java.net URI)))

(set! *warn-on-reflection* true)

(defn- with-session-id
  "Bridge `::session/session.id` → `::session/id` so `session/delete-fn`
  can drop the backing server-side row. Mirrors the helper in
  app.http.auth-request used by the same primitive."
  [request]
  (if-let [sid (some-> request ::session/session :id)]
    (assoc request ::session/id sid)
    request))

(defn- allowed-next?
  "True iff `url` is a safe redirect target:
    - scheme is http or https
    - host equals PLATFORM_DOMAIN or is a subdomain
  Suffix match enforces a dot boundary so `foss.arbisoft.com.evil` does
  NOT match `foss.arbisoft.com`. Unset PLATFORM_DOMAIN → false (every
  next= rejected)."
  [url]
  (let [platform-domain (some-> (cf/get :platform-domain) str/lower str/trim
                                (str/strip-prefix \".\"))]
    (when (and platform-domain (seq platform-domain))
      (try
        (let [uri    (URI. url)
              scheme (some-> (.getScheme uri) str/lower)
              host   (some-> (.getHost uri) str/lower)]
          (and host
               (or (= scheme "http") (= scheme "https"))
               (or (= host platform-domain)
                   (str/ends-with? host (str "." platform-domain)))))
        (catch Throwable _ false)))))

(defn- handler
  [cfg request]
  (let [delete-session! (session/delete-fn cfg)
        next-url        (some-> request :params :next str/trim)
        base-response   (if (and next-url (seq next-url) (allowed-next? next-url))
                          {::yres/status 302
                           ::yres/headers {"Location" next-url}}
                          {::yres/status 200
                           ::yres/body ""})]
    ;; delete-fn attaches the Set-Cookie that expires auth-token, in
    ;; addition to dropping the backing server-side row. Returns the
    ;; response unchanged when no session is present (e.g. user already
    ;; logged out by a previous step in the chain).
    (delete-session! (with-session-id request) base-response)))

(defmethod ig/assert-key ::routes
  [_ params]
  (assert (contains? params ::session/manager)
          "portal-logout requires ::session/manager"))

(defmethod ig/init-key ::routes
  [_ cfg]
  ["/api/auth/portal-logout"
   {:handler        (partial handler cfg)
    :allowed-methods #{:get}}])
