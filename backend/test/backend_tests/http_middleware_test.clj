;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/.
;;
;; Copyright (c) KALEIDOS SUBSIDIARY SL

(ns backend-tests.http-middleware-test
  (:require
   [app.common.exceptions :as ex]
   [app.common.json :as json]
   [app.common.time :as ct]
   [app.common.uuid :as uuid]
   [app.config :as cf]
   [app.db :as db]
   [app.http :as-alias http]
   [app.http.access-token :as access-token]
   [app.http.auth-request]
   [app.http.errors :as http-errors]
   [app.http.middleware :as mw]
   [app.http.session :as session]
   [app.main :as main]
   [app.metrics :as mtx]
   [app.rpc :as-alias rpc]
   [app.rpc.commands.access-token]
   [app.rpc.commands.profile :as profile]
   [app.storage.schema :as stsch]
   [app.tokens :as tokens]
   [backend-tests.helpers :as th]
   [backend-tests.mpass-tokens :as tk]
   [clojure.string :as str]
   [clojure.test :as t]
   [integrant.core :as ig]
   [mockery.core :refer [with-mocks]]
   [yetti.request :as yreq]
   [yetti.response :as yres])
  (:import
   io.prometheus.client.CollectorRegistry
   io.undertow.server.RequestTooBigException))

(def ^:private test-edge-secret
  "0123456789abcdef0123456789abcdef0123456789abcdef")

(defn- with-test-edge-secret
  [next]
  (binding [cf/config (assoc cf/config :mpass-edge-secret test-edge-secret)]
    (next)))

(t/use-fixtures :once th/state-init)
(t/use-fixtures :each th/database-reset with-test-edge-secret)

(defn- edge-request
  "A request as Traefik forwards it from the SSO router: carrying the
  edge secret next to the identity headers."
  [params]
  (th/make-dummy-request (update params :headers assoc "x-mpass-edge-secret" test-edge-secret)))

(t/deftest auth-middleware-1
  (let [request (volatile! nil)
        handler (#'app.http.middleware/wrap-auth
                 (fn [req] (vreset! request req))
                 {})]

    (handler (th/make-dummy-request {}))

    (t/is (nil? (::http/auth-data @request)))

    (handler (th/make-dummy-request {:headers {"authorization" "Token aaaa"}}))

    (let [{:keys [token claims] token-type :type} (get @request ::http/auth-data)]
      (t/is (= :token token-type))
      (t/is (= "aaaa" token))
      (t/is (nil? claims)))))

(t/deftest auth-middleware-2
  (let [request (volatile! nil)
        handler (#'app.http.middleware/wrap-auth
                 (fn [req] (vreset! request req))
                 {})]

    (handler (th/make-dummy-request {}))
    (t/is (nil? (::http/auth-data @request)))

    ;; A bearer token is only attached when it is a current session
    ;; token (kid=1/ver=1) and a decoder is configured. Otherwise the
    ;; request stays unauthenticated.
    (handler (th/make-dummy-request {:headers {"authorization" "Bearer aaaa"}}))
    (t/is (nil? (::http/auth-data @request)))))

(t/deftest auth-middleware-3
  (let [request (volatile! nil)
        handler (#'app.http.middleware/wrap-auth
                 (fn [req] (vreset! request req))
                 {})]

    (handler (th/make-dummy-request {}))
    (t/is (nil? (::http/auth-data @request)))

    (handler (th/make-dummy-request {:cookies {"auth-token" "foobar"}}))
    (t/is (nil? (::http/auth-data @request)))))

(t/deftest shared-key-auth
  (let [handler (#'app.http.middleware/wrap-shared-key-auth
                 (fn [req] {::yres/status 200})
                 {:test1 "secret-key"})]

    (let [response (handler (th/make-dummy-request {}))]
      (t/is (= 403 (::yres/status response))))

    (let [response (handler (th/make-dummy-request {:headers {"x-shared-key" "secret-key2"}}))]
      (t/is (= 403 (::yres/status response))))

    (let [response (handler (th/make-dummy-request {:headers {"x-shared-key" "secret-key"}}))]
      (t/is (= 403 (::yres/status response))))

    (let [response (handler (th/make-dummy-request {:headers {"x-shared-key" "test1 secret-key"}}))]
      (t/is (= 200 (::yres/status response))))))

(t/deftest access-token-authz
  (let [profile (th/create-profile* 1)
        token   (db/tx-run! th/*system* app.rpc.commands.access-token/create-access-token (:id profile) "test" nil nil)
        handler (#'app.http.access-token/wrap-authz identity th/*system*)]

    (let [response (handler nil)]
      (t/is (nil? response)))

    (let [response (handler {::http/auth-data {:type :token :token "foobar" :claims {:tid (:id token)}}})]
      (t/is (= #{} (:app.http.access-token/perms response)))
      (t/is (= (:id profile) (:app.http.access-token/profile-id response))))))

(t/deftest access-token-authz-sets-token-id-and-type
  (let [profile (th/create-profile* 1)
        token   (db/tx-run! th/*system* app.rpc.commands.access-token/create-access-token
                            (:id profile) "test" nil "mcp")
        handler (#'app.http.access-token/wrap-authz identity th/*system*)
        request {::http/auth-data {:type :token :token "foobar" :claims {:tid (:id token)}}}
        response (handler request)]
    ;; Must set ::actoken/id from claims :tid
    (t/is (= (:id token) (:app.http.access-token/id response)))
    ;; Must set ::actoken/type from database
    (t/is (= "mcp" (:app.http.access-token/type response)))
    ;; Existing assertions still pass
    (t/is (= #{} (:app.http.access-token/perms response)))
    (t/is (= (:id profile) (:app.http.access-token/profile-id response)))))

(defrecord MethodAwareDummyRequest [req-method headers]
  yreq/IRequest
  (method [_] req-method)
  (get-header [_ name] (get headers name)))

(t/deftest cors-middleware-allowlisted-origin
  (let [handler (#'app.http.middleware/wrap-cors
                 (fn [_] {::yres/status 200 ::yres/headers {}})
                 #{"https://trusted.example"})
        resp    (handler (->MethodAwareDummyRequest :get {"origin" "https://trusted.example"}))
        headers (::yres/headers resp)]

    (t/is (= 200 (::yres/status resp)))
    (t/is (= "https://trusted.example" (get headers "access-control-allow-origin")))
    (t/is (= "true" (get headers "access-control-allow-credentials")))
    (t/is (= "Origin" (get headers "vary")))
    (t/is (= "content-type, retry-after, x-rate-limit-remaining, x-rate-limit-reset"
             (get headers "access-control-expose-headers")))
    (t/is (not (str/includes?
                (get headers "access-control-allow-headers" "")
                "cookie")))))

(t/deftest cors-middleware-non-allowlisted-origin
  (let [handler (#'app.http.middleware/wrap-cors
                 (fn [_] {::yres/status 200 ::yres/headers {}})
                 #{"https://trusted.example"})
        resp    (handler (->MethodAwareDummyRequest :get {"origin" "https://attacker.example"}))
        headers (::yres/headers resp)]

    (t/is (= 200 (::yres/status resp)))
    (t/is (nil? (get headers "access-control-allow-origin")))
    (t/is (nil? (get headers "access-control-allow-credentials")))
    (t/is (nil? (get headers "access-control-allow-headers")))
    (t/is (nil? (get headers "access-control-expose-headers")))
    (t/is (= "Origin" (get headers "vary")))))

(t/deftest cors-middleware-preflight-allowlisted
  (let [handler (#'app.http.middleware/wrap-cors
                 (fn [_] {::yres/status 200 ::yres/headers {}})
                 #{"https://trusted.example"})
        resp    (handler (->MethodAwareDummyRequest :options {"origin" "https://trusted.example"}))
        headers (::yres/headers resp)]

    (t/is (= 204 (::yres/status resp)))
    (t/is (= "https://trusted.example" (get headers "access-control-allow-origin")))
    (t/is (= "true" (get headers "access-control-allow-credentials")))))

(t/deftest cors-middleware-preflight-non-allowlisted
  (let [handler (#'app.http.middleware/wrap-cors
                 (fn [_] {::yres/status 200 ::yres/headers {}})
                 #{"https://trusted.example"})
        resp    (handler (->MethodAwareDummyRequest :options {"origin" "https://attacker.example"}))
        headers (::yres/headers resp)]

    (t/is (= 204 (::yres/status resp)))
    (t/is (nil? (get headers "access-control-allow-origin")))
    (t/is (nil? (get headers "access-control-allow-credentials")))))

(t/deftest cors-middleware-missing-origin
  (let [handler (#'app.http.middleware/wrap-cors
                 (fn [_] {::yres/status 200 ::yres/headers {}})
                 #{"https://trusted.example"})
        resp    (handler (->MethodAwareDummyRequest :get {}))
        headers (::yres/headers resp)]

    (t/is (= 200 (::yres/status resp)))
    (t/is (nil? (get headers "access-control-allow-origin")))
    (t/is (nil? (get headers "access-control-allow-credentials")))))

(t/deftest session-authz
  (let [cfg      th/*system*
        manager  (session/inmemory-manager)
        profile  (th/create-profile* 1)
        handler  (-> (fn [req] req)
                     (#'session/wrap-authz  {::session/manager manager})
                     (#'mw/wrap-auth {:bearer (partial session/decode-token cfg)
                                      :cookie (partial session/decode-token cfg)}))

        session  (->> (session/create-session manager {:profile-id (:id profile)
                                                       :user-agent "user agent"})
                      (#'session/assign-token cfg))

        response (handler (th/make-dummy-request {:cookies {"auth-token" (:token session)}}))

        {:keys [token claims] token-type :type}
        (get response ::http/auth-data)]

    (t/is (= :cookie token-type))
    (t/is (= (:token session) token))
    (t/is (= "authentication" (:iss claims)))
    (t/is (= "penpot" (:aud claims)))
    (t/is (= (:id session) (:sid claims)))
    (t/is (= (:id profile) (:uid claims)))))

(t/deftest session-authz-does-not-renew-on-error-response
  ;; The renewal guard MUST also step aside on error responses.
  ;; Without this, a 403 produced by wrap-authz (proxy identity
  ;; mismatch with a blocked/inactive incoming profile) would still
  ;; cause alice's session cookie to be renewed on the way out —
  ;; extending her session lifetime on the very denial that signaled
  ;; her identity is no longer valid upstream.
  (let [cfg       th/*system*
        manager   (session/inmemory-manager)
        profile   (th/create-profile* 91)
        t0        (ct/inst "2025-01-01T00:00:00Z")
        t1        (ct/plus t0 (ct/duration {:seconds 2}))
        threshold (ct/duration {:seconds 1})
        handler   (-> (fn [_req] {::yres/status 403})
                      (#'session/wrap-authz {::session/manager manager})
                      (#'mw/wrap-auth {:bearer (partial session/decode-token cfg)
                                       :cookie (partial session/decode-token cfg)}))
        token     (binding [ct/*clock* (ct/fixed-clock t0)]
                    (->> (session/create-session manager {:profile-id (:id profile)
                                                          :user-agent "user agent"})
                         (#'session/assign-token cfg)))
        response  (binding [cf/config (assoc cf/config :auth-token-cookie-renewal-max-age threshold)
                            ct/*clock* (ct/fixed-clock t1)]
                    (handler (th/make-dummy-request {:cookies {"auth-token" (:token token)}})))]
    (t/is (= 403 (::yres/status response)))
    (t/is (not (contains? (::yres/cookies response) "auth-token")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; X-Auth-Request middleware tests
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- make-xauth-cfg
  []
  (assoc th/*system* ::session/manager (session/inmemory-manager)))

(t/deftest x-auth-request-no-email-header
  (let [captured (volatile! nil)
        handler  (#'app.http.auth-request/wrap-authz
                  (fn [req] (vreset! captured req) {::yres/status 200})
                  (make-xauth-cfg))]
    (handler (th/make-dummy-request {}))
    (t/is (nil? (::session/profile-id @captured)))))

(t/deftest x-auth-request-preserves-session-when-header-email-unresolvable
  ;; When wrap-session has resolved alice's profile-id from the local
  ;; auth-token cookie AND the proxy header email cannot be resolved to
  ;; a profile (unknown user + auto-register off), the existing session
  ;; passes through unchanged. The middleware only re-keys when it has
  ;; a *real* alternative identity to switch to.
  (let [profile-id (random-uuid)
        handler    (#'app.http.auth-request/wrap-authz
                    (fn [req] req)
                    (make-xauth-cfg))
        request    (-> (edge-request {:headers {"x-auth-request-email" "user@example.com"}})
                       (assoc ::session/profile-id profile-id))
        result     (handler request)]
    (t/is (= profile-id (::session/profile-id result)))))

(t/deftest x-auth-request-rekeys-when-session-identity-differs
  ;; Repro of the QA-reported session-sharing bug: alice's auth-token
  ;; cookie persists on Penpot's subdomain after the portal "log out of
  ;; all apps"; bob then logs in upstream. wrap-session resolves alice's
  ;; profile-id from the old cookie, but oauth2-proxy is forwarding
  ;; bob's email. The middleware MUST re-key to bob.
  (let [alice    (th/create-profile* 1 {:is-active true})
        bob      (th/create-profile* 2 {:is-active true})
        captured (volatile! nil)
        cfg      (make-xauth-cfg)
        handler  (#'app.http.auth-request/wrap-authz
                  (fn [req] (vreset! captured req) {::yres/status 200})
                  cfg)
        request  (-> (edge-request {:headers {"x-auth-request-email" (:email bob)}})
                     (assoc ::session/profile-id (:id alice)))
        response (handler request)]
    ;; Downstream handler sees bob's profile-id, not alice's.
    (t/is (= (:id bob) (::session/profile-id @captured)))
    ;; A fresh auth-token cookie is issued for bob's session.
    (t/is (contains? (::yres/cookies response) "auth-token"))))

(t/deftest x-auth-request-no-rekey-when-session-matches-header
  ;; Steady-state guard: the browser session matches the proxy identity.
  ;; No re-key, no new cookie. Without this, every authenticated request
  ;; would mint a fresh cookie.
  (let [profile  (th/create-profile* 1 {:is-active true})
        captured (volatile! nil)
        cfg      (make-xauth-cfg)
        handler  (#'app.http.auth-request/wrap-authz
                  (fn [req] (vreset! captured req) {::yres/status 200})
                  cfg)
        request  (-> (edge-request {:headers {"x-auth-request-email" (:email profile)}})
                     (assoc ::session/profile-id (:id profile)))
        response (handler request)]
    (t/is (= (:id profile) (::session/profile-id @captured)))
    (t/is (not (contains? (::yres/cookies response) "auth-token")))))

(t/deftest x-auth-request-rekey-clears-stale-auth-data
  ;; The re-keyed request must have ::http/auth-data removed before the
  ;; inner handler runs. errors.clj logs auth-data.claims.uid as
  ;; :request/profile-id and rpc/helpers exposes the map to RPC
  ;; handlers via get-auth-data — both would otherwise see alice's UID
  ;; after we re-keyed to bob, leaking the stale identity across the
  ;; boundary the middleware thinks it has crossed.
  (let [alice    (th/create-profile* 1 {:is-active true})
        bob      (th/create-profile* 2 {:is-active true})
        captured (volatile! nil)
        cfg      (make-xauth-cfg)
        handler  (#'app.http.auth-request/wrap-authz
                  (fn [req] (vreset! captured req) {::yres/status 200})
                  cfg)
        request  (-> (edge-request {:headers {"x-auth-request-email" (:email bob)}})
                     (assoc ::session/profile-id (:id alice))
                     (assoc ::http/auth-data {:type :cookie
                                              :claims {:uid (:id alice)
                                                       :sid (random-uuid)}}))]
    (handler request)
    (t/is (= (:id bob) (::session/profile-id @captured)))
    (t/is (nil? (::http/auth-data @captured)))))

(t/deftest x-auth-request-rekey-clears-stale-session-map
  ;; ::session/session is read indirectly by session/get-session, which
  ;; the update-profile-password RPC calls via invalidate-others. If
  ;; alice's stale session map survives the re-key to bob, a password-
  ;; change made on this request would invalidate alice's other
  ;; sessions instead of bob's. Surfaced by Copilot review on PR #22.
  (let [alice         (th/create-profile* 1 {:is-active true})
        bob           (th/create-profile* 2 {:is-active true})
        alice-session {:id (random-uuid)
                       :profile-id (:id alice)
                       :user-agent "alice's ua"}
        captured      (volatile! nil)
        cfg           (make-xauth-cfg)
        handler       (#'app.http.auth-request/wrap-authz
                       (fn [req] (vreset! captured req) {::yres/status 200})
                       cfg)
        request       (-> (edge-request {:headers {"x-auth-request-email" (:email bob)}})
                          (assoc ::session/profile-id (:id alice))
                          (assoc ::session/session alice-session))]
    (handler request)
    (t/is (= (:id bob) (::session/profile-id @captured)))
    (t/is (nil? (::session/session @captured)))))

(t/deftest session-authz-renewal-does-not-overwrite-rekeyed-cookie
  ;; Integration guard: session/wrap-authz runs AFTER wrap-authz on the
  ;; way out and would normally renew the incoming session cookie. If
  ;; wrap-authz has already issued a fresh auth-token cookie for the
  ;; re-keyed identity (bob), the renewal MUST step aside — otherwise
  ;; alice's renewed cookie clobbers bob's fresh one and the re-key is
  ;; silently undone.
  ;;
  ;; This locks in the (not (contains? response cookies "auth-token"))
  ;; guard added to session.clj. A future refactor that removes it
  ;; fails this test.
  (let [alice          (th/create-profile* 91 {:is-active true})
        bob            (th/create-profile* 92 {:is-active true})
        cfg            (make-xauth-cfg)
        t0             (ct/inst "2025-01-01T00:00:00Z")
        t1             (ct/plus t0 (ct/duration {:seconds 2}))
        ;; Lower than (t1 - t0) so the seeded cookie is always due for renewal.
        renewal-threshold (ct/duration {:seconds 1})
        middleware     (-> (fn [req] {::yres/status 200
                                      :seen-profile-id (::session/profile-id req)})
                           (#'app.http.auth-request/wrap-authz cfg)
                           (#'session/wrap-authz cfg)
                           (#'mw/wrap-auth {:bearer (partial session/decode-token cfg)
                                            :cookie (partial session/decode-token cfg)}))
        seeded-token   (binding [ct/*clock* (ct/fixed-clock t0)]
                         (get-in ((session/create-fn cfg alice)
                                  (th/make-dummy-request {})
                                  {::yres/status 200})
                                 [::yres/cookies "auth-token" :value]))
        response       (binding [cf/config (assoc cf/config
                                                  :auth-token-cookie-renewal-max-age
                                                  renewal-threshold)
                                 ct/*clock* (ct/fixed-clock t1)]
                         (middleware (edge-request {:headers {"x-auth-request-email" (:email bob)}
                                                    :cookies {"auth-token" seeded-token}})))
        rekeyed-token  (get-in response [::yres/cookies "auth-token" :value])
        followup       (binding [ct/*clock* (ct/fixed-clock t1)]
                         (middleware (th/make-dummy-request {:cookies {"auth-token" rekeyed-token}})))]
    ;; Cookie was re-keyed (not just renewed): the new token differs.
    (t/is (some? rekeyed-token))
    (t/is (not= seeded-token rekeyed-token))
    ;; This request's inner handler ran as bob, not alice.
    (t/is (= (:id bob) (:seen-profile-id response)))
    ;; The re-keyed token, decoded on a follow-up request, still resolves to bob.
    ;; If renewal had clobbered the response cookie with a renewed alice token,
    ;; this would resolve to alice instead.
    (t/is (= (:id bob) (:seen-profile-id followup)))))

(t/deftest x-auth-request-skips-when-access-token-present
  (let [profile-id (random-uuid)
        handler    (#'app.http.auth-request/wrap-authz
                    (fn [req] req)
                    (make-xauth-cfg))
        request    (-> (edge-request {:headers {"x-auth-request-email" "user@example.com"}})
                       (assoc ::access-token/profile-id profile-id))
        result     (handler request)]
    (t/is (= profile-id (::access-token/profile-id result)))))

(t/deftest x-auth-request-authenticates-existing-active-profile
  (let [profile  (th/create-profile* 1 {:is-active true})
        captured (volatile! nil)
        cfg      (make-xauth-cfg)
        handler  (#'app.http.auth-request/wrap-authz
                  (fn [req] (vreset! captured req) {::yres/status 200})
                  cfg)
        response (handler (edge-request {:headers {"x-auth-request-email" (:email profile)}}))]
    ;; The profile-id must be injected into the request seen by the downstream handler
    (t/is (= (:id profile) (::session/profile-id @captured)))
    ;; A session cookie must be set on the response
    (t/is (contains? (::yres/cookies response) "auth-token"))))

(t/deftest x-auth-request-blocked-profile-returns-403
  (let [profile  (th/create-profile* 2 {:is-active true})
        _        (th/db-update! :profile {:is-blocked true} {:id (:id profile)})
        handler  (#'app.http.auth-request/wrap-authz
                  (fn [_] {::yres/status 200})
                  (make-xauth-cfg))
        response (handler (edge-request {:headers {"x-auth-request-email" (:email profile)}}))]
    (t/is (= 403 (::yres/status response)))))

(t/deftest x-auth-request-inactive-profile-returns-403
  (let [profile  (th/create-profile* 3 {:is-active false})
        handler  (#'app.http.auth-request/wrap-authz
                  (fn [_] {::yres/status 200})
                  (make-xauth-cfg))
        response (handler (edge-request {:headers {"x-auth-request-email" (:email profile)}}))]
    (t/is (= 403 (::yres/status response)))))

(t/deftest x-auth-request-unknown-email-no-autoregister
  (let [captured (volatile! nil)
        handler  (#'app.http.auth-request/wrap-authz
                  (fn [req] (vreset! captured req) {::yres/status 200})
                  (make-xauth-cfg))]
    (handler (edge-request {:headers {"x-auth-request-email" "nobody@example.com"}}))
    (t/is (nil? (::session/profile-id @captured)))))

(t/deftest x-auth-request-auto-register-creates-active-profile
  (binding [cf/flags (conj cf/flags :x-auth-request-auto-register)]
    (let [email    "newuser@example.com"
          captured (volatile! nil)
          cfg      (make-xauth-cfg)
          handler  (#'app.http.auth-request/wrap-authz
                    (fn [req] (vreset! captured req) {::yres/status 200})
                    cfg)
          ;; Regression guard: oauth2-proxy set x-auth-request-user to the
          ;; Cognito sub UUID. The middleware must IGNORE that header and derive
          ;; :fullname from the email local-part — sending it here proves it is
          ;; not trusted for the display name.
          response (handler (edge-request {:headers {"x-auth-request-email" email
                                                     "x-auth-request-user" "892ae5ac-0021-7000-8000-000000000000"}}))]
      ;; Profile must be injected into the downstream request
      (t/is (uuid? (::session/profile-id @captured)))
      ;; A session cookie must be set so the browser is authenticated
      (t/is (contains? (::yres/cookies response) "auth-token"))
      ;; The created profile must be active and match the forwarded email
      (let [profile (db/tx-run! cfg
                                (fn [{:keys [::db/conn]}]
                                  (profile/get-profile-by-email conn email)))]
        (t/is (some? profile))
        (t/is (true? (:is-active profile)))
        ;; Derived from the email local-part, NOT the x-auth-request-user UUID.
        (t/is (= "newuser" (:fullname profile)))
        (t/is (= (::session/profile-id @captured) (:id profile)))))))

(t/deftest x-auth-request-auto-register-joins-named-smb-team
  (binding [cf/flags  (conj cf/flags :x-auth-request-auto-register)
            cf/config (assoc cf/config :smb-default-workspace-name "team1")]
    (let [owner    (th/create-profile* 1 {:is-active true})
          ;; Matches :smb-default-workspace-name "team1" from create-team* default name.
          _        (th/create-team* 1 {:profile-id (:id owner)})
          email    "xauth-autojoin@example.com"
          captured (volatile! nil)
          cfg      (make-xauth-cfg)
          handler  (#'app.http.auth-request/wrap-authz
                    (fn [req] (vreset! captured req) {::yres/status 200})
                    cfg)
          _        (handler (edge-request {:headers {"x-auth-request-email" email}}))
          profile  (db/tx-run! cfg
                               (fn [{:keys [::db/conn]}]
                                 (profile/get-profile-by-email conn email)))
          rels     (db/query th/*pool* :team-profile-rel {:profile-id (:id profile)})]
      (t/is (uuid? (:id profile)))
      (t/is (some #(not= (:team-id %) (:default-team-id profile)) rels)
            "profile should have a membership on the provisioned SMB (shared) team"))))

;; X-Auth-Request edge trust and corporate gate (FOSS-781)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- capturing-handler
  ([captured] (capturing-handler captured (make-xauth-cfg)))
  ([captured cfg]
   (#'app.http.auth-request/wrap-authz
    (fn [req] (vreset! captured req) {::yres/status 200})
    cfg)))

(defn- assert-ignored
  [request]
  (binding [cf/flags (conj cf/flags :x-auth-request-auto-register)]
    (let [captured (volatile! nil)
          response ((capturing-handler captured) request)]
      (t/is (= 200 (::yres/status response)))
      (t/is (nil? (::session/profile-id @captured)))
      (t/is (not (contains? (::yres/cookies response) "auth-token")))
      (t/is (empty? (db/query th/*pool* :profile {:email "victim@example.com"}))))))

(t/deftest x-auth-request-forged-header-without-edge-secret-is-ignored
  (assert-ignored (th/make-dummy-request {:headers {"x-auth-request-email" "victim@example.com"
                                                    "x-auth-request-user" "victim"}})))

(t/deftest x-auth-request-forged-header-with-wrong-edge-secret-is-ignored
  (assert-ignored (th/make-dummy-request {:headers {"x-auth-request-email" "victim@example.com"
                                                    "x-mpass-edge-secret" (str test-edge-secret "x")}})))

(t/deftest x-auth-request-short-edge-secret-trusts-nothing
  (binding [cf/config (assoc cf/config :mpass-edge-secret "too-short")]
    (assert-ignored (th/make-dummy-request {:headers {"x-auth-request-email" "victim@example.com"
                                                      "x-mpass-edge-secret" "too-short"}}))))

(t/deftest x-auth-request-placeholder-edge-secret-trusts-nothing
  (let [placeholder "CHANGE_ME_PENPOT_EDGE_SECRET_0123456789abcdef"]
    (binding [cf/config (assoc cf/config :mpass-edge-secret placeholder)]
      (assert-ignored (th/make-dummy-request {:headers {"x-auth-request-email" "victim@example.com"
                                                        "x-mpass-edge-secret" placeholder}})))))

(t/deftest x-auth-request-unset-edge-secret-trusts-nothing
  (binding [cf/config (dissoc cf/config :mpass-edge-secret)]
    (assert-ignored (th/make-dummy-request {:headers {"x-auth-request-email" "victim@example.com"
                                                      "x-mpass-edge-secret" ""}}))))

(t/deftest x-auth-request-forged-header-does-not-rekey-existing-session
  (let [alice    (th/create-profile* 1 {:is-active true})
        bob      (th/create-profile* 2 {:is-active true})
        captured (volatile! nil)
        request  (-> (th/make-dummy-request {:headers {"x-auth-request-email" (:email bob)}})
                     (assoc ::session/profile-id (:id alice)))
        response ((capturing-handler captured) request)]
    (t/is (= (:id alice) (::session/profile-id @captured)))
    (t/is (not (contains? (::yres/cookies response) "auth-token")))))

(t/deftest x-auth-request-access-token-path-ignores-forged-headers
  (let [profile-id (random-uuid)
        captured   (volatile! nil)
        request    (-> (th/make-dummy-request {:headers {"x-auth-request-email" "victim@example.com"}})
                       (assoc ::access-token/profile-id profile-id))
        response   ((capturing-handler captured) request)]
    (t/is (= 200 (::yres/status response)))
    (t/is (= profile-id (::access-token/profile-id @captured)))
    (t/is (nil? (::session/profile-id @captured)))))

(defn- gate-cfg
  [fetch]
  (assoc (make-xauth-cfg) :app.http.auth-request/token-verifier (tk/make-verifier :fetch fetch)))

(def ^:private profile-seq (atom 100))

(defn- gated-login
  [token & {:keys [fetch]}]
  (binding [cf/config (assoc cf/config :smb-corporate-id tk/corporate-id)]
    (let [profile  (th/create-profile* (swap! profile-seq inc) {:is-active true})
          captured (volatile! nil)
          handler  (capturing-handler captured (gate-cfg (or fetch (:fetch (tk/counting-fetcher)))))
          headers  (cond-> {"x-auth-request-email" (:email profile)}
                     token (assoc "x-auth-request-access-token" token))
          response (handler (edge-request {:headers headers}))]
      {:status (::yres/status response)
       :logged-in? (= (:id profile) (::session/profile-id @captured))})))

(t/deftest x-auth-request-gate-admits-verified-corporate-token
  (t/is (= {:status 200 :logged-in? true} (gated-login (tk/sign (tk/access-claims)))))
  (t/is (= {:status 200 :logged-in? true} (gated-login (tk/sign (tk/id-claims :iss tk/proxy-issuer) tk/proxy-key-pair)))))

(t/deftest x-auth-request-gate-refuses-unverified-or-foreign-tokens
  (let [refused {:status 403 :logged-in? false}]
    (t/is (= refused (gated-login nil)) "missing token")
    (t/is (= refused (gated-login (tk/sign (tk/access-claims) tk/attacker-key-pair))) "bad signature")
    (t/is (= refused (gated-login (tk/sign (tk/access-claims :exp (- (tk/now-seconds) 3600))))) "expired")
    (t/is (= refused (gated-login (tk/sign (tk/access-claims :iss "https://evil.example")))) "wrong issuer")
    (t/is (= refused (gated-login (tk/sign (tk/access-claims :client_id "other")))) "wrong audience")
    (t/is (= refused (gated-login (tk/unsigned-token (tk/access-claims)))) "alg none")
    (t/is (= refused (gated-login (tk/hs256-token (tk/access-claims)))) "HS256")
    (t/is (= refused (gated-login (tk/sign (tk/access-claims (keyword "custom:is_corporate") "false")))) "not corporate")
    (t/is (= refused (gated-login (tk/sign (tk/access-claims (keyword "custom:corporate_id") "other-corp")))) "wrong organization")))

(t/deftest x-auth-request-gate-refuses-when-jwks-is-unavailable
  (t/is (= {:status 403 :logged-in? false}
           (gated-login (tk/sign (tk/access-claims))
                        :fetch (fn [_] (throw (java.net.SocketTimeoutException. "timed out")))))))

(t/deftest x-auth-request-gate-refuses-without-a-verifier
  (binding [cf/config (assoc cf/config :smb-corporate-id tk/corporate-id)]
    (let [profile  (th/create-profile* 1 {:is-active true})
          handler  (capturing-handler (volatile! nil))
          response (handler (edge-request {:headers {"x-auth-request-email" (:email profile)
                                                     "x-auth-request-access-token" (tk/sign (tk/access-claims))}}))]
      (t/is (= 403 (::yres/status response))))))

(t/deftest x-auth-request-gate-unset-reads-no-token
  (binding [cf/config (dissoc cf/config :smb-corporate-id)]
    (let [{:keys [calls fetch]} (tk/counting-fetcher)
          profile               (th/create-profile* 1 {:is-active true})
          captured              (volatile! nil)
          handler               (capturing-handler captured (gate-cfg fetch))
          response              (handler (edge-request {:headers {"x-auth-request-email" (:email profile)
                                                                  "x-auth-request-access-token" "not-a-jwt"}}))]
      (t/is (= 200 (::yres/status response)))
      (t/is (= (:id profile) (::session/profile-id @captured)))
      (t/is (= 0 @calls)))))

(defn- gated-request
  [{:keys [profile session-pid token fetch]}]
  (binding [cf/config (assoc cf/config :smb-corporate-id tk/corporate-id)]
    (let [captured (volatile! nil)
          handler  (capturing-handler captured (gate-cfg (or fetch (:fetch (tk/counting-fetcher)))))
          headers  (cond-> {"x-auth-request-email" (:email profile)}
                     token (assoc "x-auth-request-access-token" token))
          request  (cond-> (edge-request {:headers headers})
                     session-pid (assoc ::session/profile-id session-pid))
          response (handler request)]
      {:status (::yres/status response)
       :profile-id (::session/profile-id @captured)})))

(defn- failing-fetch
  [_]
  (throw (java.net.SocketTimeoutException. "timed out")))

(t/deftest x-auth-request-gate-is-lenient-on-an-established-session
  (let [profile (th/create-profile* (swap! profile-seq inc) {:is-active true})
        passes  {:status 200 :profile-id (:id profile)}
        request #(gated-request (merge {:profile profile :session-pid (:id profile)} %))]
    (t/is (= passes (request {:token (tk/sign (tk/access-claims :exp (- (tk/now-seconds) 3600)))})) "expired")
    (t/is (= passes (request {:token (tk/sign (tk/access-claims)) :fetch failing-fetch})) "jwks unavailable")
    (t/is (= passes (request {:token nil})) "missing token")
    (t/is (= passes (request {:token (tk/sign (tk/access-claims) tk/attacker-key-pair)})) "unverifiable signature")
    (t/is (= {:status 403 :profile-id nil}
             (request {:token (tk/sign (tk/access-claims (keyword "custom:corporate_id") "other-corp"))}))
          "signed wrong organization")
    (t/is (= {:status 403 :profile-id nil}
             (request {:token (tk/sign (tk/access-claims (keyword "custom:is_corporate") "false"))}))
          "signed not corporate")))

(t/deftest x-auth-request-gate-is-strict-when-re-keying
  (let [alice (th/create-profile* (swap! profile-seq inc) {:is-active true})
        bob   (th/create-profile* (swap! profile-seq inc) {:is-active true})]
    (t/is (= {:status 403 :profile-id nil}
             (gated-request {:profile bob :session-pid (:id alice)
                             :token (tk/sign (tk/access-claims :exp (- (tk/now-seconds) 3600)))})))
    (t/is (= {:status 403 :profile-id nil}
             (gated-request {:profile bob :session-pid (:id alice)
                             :token (tk/sign (tk/access-claims)) :fetch failing-fetch})))
    (t/is (= {:status 200 :profile-id (:id bob)}
             (gated-request {:profile bob :session-pid (:id alice) :token (tk/sign (tk/access-claims))})))))

(t/deftest x-auth-request-placeholder-corporate-id-refuses-everyone
  (binding [cf/config (assoc cf/config :smb-corporate-id "  CHANGE_ME_SMB_CORPORATE_ID ")]
    (let [{:keys [calls fetch]} (tk/counting-fetcher)
          alice    (th/create-profile* (swap! profile-seq inc) {:is-active true})
          bob      (th/create-profile* (swap! profile-seq inc) {:is-active true})
          captured (volatile! nil)
          handler  (capturing-handler captured (gate-cfg fetch))
          token    (tk/sign (tk/access-claims))
          send     (fn [profile session-pid]
                     (handler (cond-> (edge-request {:headers {"x-auth-request-email" (:email profile)
                                                               "x-auth-request-access-token" token}})
                                session-pid (assoc ::session/profile-id session-pid))))]
      (t/is (= 403 (::yres/status (send alice nil))) "establishing a session")
      (t/is (= 403 (::yres/status (send bob (:id alice)))) "re-keying a session")
      (t/is (= 403 (::yres/status (send alice (:id alice)))) "established session")
      (t/is (= 0 @calls) "no token is verified"))))

(t/deftest x-auth-request-blank-corporate-id-keeps-the-gate-off
  (binding [cf/config (assoc cf/config :smb-corporate-id "   ")]
    (let [profile  (th/create-profile* (swap! profile-seq inc) {:is-active true})
          captured (volatile! nil)
          handler  (capturing-handler captured (gate-cfg failing-fetch))
          response (handler (edge-request {:headers {"x-auth-request-email" (:email profile)}}))]
      (t/is (= 200 (::yres/status response)))
      (t/is (= (:id profile) (::session/profile-id @captured))))))

(t/deftest x-auth-request-with-token-verifier-builds-one-verifier
  (binding [cf/flags (conj cf/flags :x-auth-request-headers)]
    (t/is (some? (:app.http.auth-request/token-verifier
                  (app.http.auth-request/with-token-verifier {})))))
  (binding [cf/flags (disj cf/flags :x-auth-request-headers)]
    (t/is (= {} (app.http.auth-request/with-token-verifier {})))))

(t/deftest session-token-contains-exp-claim
  (let [cfg     th/*system*
        manager (session/inmemory-manager)
        profile (th/create-profile* 1)
        session (->> (session/create-session manager {:profile-id (:id profile)
                                                      :user-agent "user agent"})
                     (#'session/assign-token cfg))
        claims  (tokens/decode cfg (:token session))
        exp     (:exp claims)]
    (t/is (some? exp) "session token should contain :exp claim")
    (t/is (ct/inst? exp) "exp should be an instant")))

(t/deftest session-token-exp-based-on-created-at
  (let [cfg          th/*system*
        manager      (session/inmemory-manager)
        profile      (th/create-profile* 1)
        session      (->> (session/create-session manager {:profile-id (:id profile)
                                                           :user-agent "user agent"})
                          (#'session/assign-token cfg))
        claims       (tokens/decode cfg (:token session))
        expected-exp (ct/plus (:created-at session) (ct/duration {:days 30}))]
    (t/is (some? (:exp claims)) "session token should contain :exp claim")
    (t/is (= (inst-ms (:exp claims))
             (inst-ms expected-exp))
          "exp should equal created-at + 30 days")))

(t/deftest session-token-past-exp-is-rejected
  (let [cfg         th/*system*
        manager     (session/inmemory-manager)
        profile     (th/create-profile* 1)
        session     (->> (session/create-session manager {:profile-id (:id profile)
                                                          :user-agent "user agent"})
                         (#'session/assign-token cfg))
        claims      (tokens/decode cfg (:token session))
        past-claims (assoc claims :exp (ct/minus (ct/now) (ct/duration {:days 1})))
        past-token  (tokens/generate cfg past-claims {:kid 1 :ver 1})]
    (t/is (nil? (session/decode-token cfg past-token))
          "token with exp in the past should be rejected")))

(t/deftest session-renewal-preserves-original-exp
  (let [cfg      th/*system*
        profile  (th/create-profile* 1)
        created  (ct/minus (ct/now) (ct/duration {:days 1}))
        session  {:id          (uuid/random)
                  :profile-id  (:id profile)
                  :user-agent  "user agent"
                  :created-at  created
                  :modified-at (ct/minus (ct/now) (ct/duration {:hours 7}))}
        manager  (reify session/ISessionManager
                   (read-session [_ _] session)
                   (create-session [_ _] session)
                   (update-session [_ s] (assoc s :modified-at (ct/now)))
                   (delete-session [_ _] nil))

        old-token      (:token (#'session/assign-token cfg session))
        original-exp   (:exp (tokens/decode cfg old-token))
        handler        (-> (fn [req] req)
                           (#'session/wrap-authz (assoc th/*system* ::session/manager manager))
                           (#'mw/wrap-auth {:bearer (partial session/decode-token cfg)
                                            :cookie (partial session/decode-token cfg)}))
        response       (handler (th/make-dummy-request {:cookies {"auth-token" old-token}}))
        renewed-token  (get-in response [::yres/cookies "auth-token" :value])
        renewed-claims (tokens/decode cfg renewed-token)]
    (t/is (some? original-exp) "original token should have :exp")
    (t/is (not= old-token renewed-token) "renewal should issue a new token string")
    (t/is (= (inst-ms original-exp) (inst-ms (:exp renewed-claims)))
          "renewed token should preserve the original :exp, not extend it")))

(t/deftest session-renewal-preserves-exp-with-db-manager
  (let [cfg          th/*system*
        manager      (::session/manager th/*system*)
        profile      (th/create-profile* 1)
        created      (session/create-session manager {:profile-id (:id profile)
                                                      :user-agent "user agent"})
        _            (th/db-exec-one! ["UPDATE http_session_v2
                                         SET modified_at = now() - interval '7 hours'
                                       WHERE id = ?" (:id created)])
        stale        (session/read-session manager (:id created))
        old-token    (:token (#'session/assign-token cfg stale))
        original-exp (:exp (tokens/decode cfg old-token))
        handler      (-> (fn [req] req)
                         (#'session/wrap-authz cfg)
                         (#'mw/wrap-auth {:bearer (partial session/decode-token cfg)
                                          :cookie (partial session/decode-token cfg)}))
        response     (handler (th/make-dummy-request {:cookies {"auth-token" old-token}}))
        renewed      (get-in response [::yres/cookies "auth-token" :value])
        renewed-exp  (:exp (tokens/decode cfg renewed))
        expected-exp (ct/plus (:created-at created) (ct/duration {:days 30}))
        current      (session/read-session manager (:id created))]
    (t/is (some? original-exp) "original token should have :exp")
    (t/is (some? renewed) "renewal should issue a new cookie token")
    (t/is (not= old-token renewed) "renewal should issue a new token string")
    (t/is (= (inst-ms original-exp) (inst-ms renewed-exp))
          "renewed token should preserve the original :exp, not extend it")
    (t/is (= (inst-ms expected-exp) (inst-ms renewed-exp))
          "renewed :exp should equal created-at + 30 days")
    (t/is (some? current) "session row must still exist after renewal")
    (t/is (pos? (compare (:modified-at current) (:modified-at stale)))
          "persisted modified_at must move forward on renewal")))

(t/deftest session-renewal-cookie-expires-diverges-from-token-exp
  (let [cfg          th/*system*
        manager      (::session/manager th/*system*)
        profile      (th/create-profile* 1)
        created      (session/create-session manager {:profile-id (:id profile)
                                                      :user-agent "user agent"})
        _            (th/db-exec-one! ["UPDATE http_session_v2
                                         SET created_at = now() - interval '29 days',
                                             modified_at = now() - interval '7 hours'
                                       WHERE id = ?" (:id created)])
        stale        (session/read-session manager (:id created))
        old-token    (:token (#'session/assign-token cfg stale))
        handler      (-> (fn [req] req)
                         (#'session/wrap-authz cfg)
                         (#'mw/wrap-auth {:bearer (partial session/decode-token cfg)
                                          :cookie (partial session/decode-token cfg)}))
        response     (handler (th/make-dummy-request {:cookies {"auth-token" old-token}}))
        cookie       (get-in response [::yres/cookies "auth-token"])
        renewed      (:value cookie)
        renewed-exp  (:exp (tokens/decode cfg renewed))
        expected-exp (ct/plus (:created-at stale) (ct/duration {:days 30}))
        close-to?    (fn [a b tolerance-ms]
                       (<= (Math/abs (- (inst-ms a) (inst-ms b))) tolerance-ms))]
    (t/is (some? renewed) "renewal should issue a new cookie token")
    (t/is (not= old-token renewed) "renewal should issue a new token string")
    (t/is (= (inst-ms expected-exp) (inst-ms renewed-exp))
          "renewed :exp should equal created-at + 30 days")
    (t/is (close-to? renewed-exp (ct/plus (ct/now) (ct/duration {:days 1}))
                     (* 10 60 1000))
          "renewed :exp should be ~1 day out (absolute cap is near)")
    (t/is (close-to? (:expires cookie) (ct/plus (ct/now) (ct/duration {:days 7}))
                     (* 10 60 1000))
          "cookie Expires should slide ~7 days out from now")
    (t/is (pos? (compare (:expires cookie) renewed-exp))
          "cookie Expires should stay ahead of the token :exp")))

(t/deftest legacy-session-token-is-rejected
  (let [cfg      th/*system*
        manager  (session/inmemory-manager)
        handler  (-> (fn [req] req)
                     (#'session/wrap-authz {::session/manager manager})
                     (#'mw/wrap-auth {:bearer (partial session/decode-token cfg)
                                      :cookie (partial session/decode-token cfg)}))
        token    (tokens/generate cfg {:sid "legacy-session-id"} {:kid 0 :ver 0})
        response (handler (th/make-dummy-request {:cookies {"auth-token" token}}))]
    (t/is (nil? (get response ::http/auth-data))
          "legacy tokens must not be attached as auth data")
    (t/is (nil? (::session/profile-id response))
          "legacy tokens must not authenticate")))

(t/deftest session-gc-deletes-idle-and-absolute-expired-rows
  (let [profile  (th/create-profile* 1)
        fresh    (uuid/random)
        idle     (uuid/random)
        absolute (uuid/random)
        valid    (uuid/random)]

    (th/db-exec-one! ["INSERT INTO http_session_v2 (id, profile_id, created_at, modified_at)
                       VALUES (?, ?, now(), now())"
                      fresh (:id profile)])
    (th/db-exec-one! ["INSERT INTO http_session_v2 (id, profile_id, created_at, modified_at)
                       VALUES (?, ?, now() - interval '1 day', now() - interval '8 days')"
                      idle (:id profile)])
    (th/db-exec-one! ["INSERT INTO http_session_v2 (id, profile_id, created_at, modified_at)
                       VALUES (?, ?, now() - interval '31 days', now())"
                      absolute (:id profile)])
    (th/db-exec-one! ["INSERT INTO http_session_v2 (id, profile_id, created_at, modified_at)
                       VALUES (?, ?, now() - interval '1 day', now() - interval '6 days')"
                      valid (:id profile)])

    (db/tx-run! th/*system*
                (fn [cfg]
                  (#'session/collect-expired-tasks
                   (assoc cfg
                          :app.http.session.tasks/max-age (ct/duration {:days 7})
                          :app.http.session.tasks/max-age-absolute (ct/duration {:days 30})))))

    (let [ids (->> (th/db-exec! ["SELECT id FROM http_session_v2 WHERE profile_id = ?" (:id profile)])
                   (map :id)
                   (set))]
      (t/is (contains? ids fresh) "fresh session must be kept")
      (t/is (contains? ids valid) "session within both windows must be kept")
      (t/is (not (contains? ids idle)) "idle session must be deleted")
      (t/is (not (contains? ids absolute)) "session past the absolute cap must be deleted"))))

(t/deftest session-gc-config-wiring
  (let [idle     (ct/duration {:days 3})
        absolute (ct/duration {:days 10})]
    (with-redefs [cf/get (fn
                           ([k] (case k
                                  :auth-token-cookie-max-age idle
                                  :auth-token-cookie-max-age-absolute absolute
                                  nil))
                           ([k default] (case k
                                          :auth-token-cookie-max-age idle
                                          :auth-token-cookie-max-age-absolute absolute
                                          default)))]
      (let [expanded (ig/expand-key :app.http.session.tasks/gc {})]
        (t/is (= idle
                 (get-in expanded [:app.http.session.tasks/gc
                                   :app.http.session.tasks/max-age]))
              "task max-age should carry the configured idle window")
        (t/is (= absolute
                 (get-in expanded [:app.http.session.tasks/gc
                                   :app.http.session.tasks/max-age-absolute]))
              "task max-age-absolute should carry the configured absolute cap")))
    (with-redefs [cf/get (fn
                           ([_k] nil)
                           ([_k default] default))]
      (let [expanded (ig/expand-key :app.http.session.tasks/gc {})]
        (t/is (= session/default-cookie-max-age
                 (get-in expanded [:app.http.session.tasks/gc
                                   :app.http.session.tasks/max-age]))
              "task max-age should fall back to the default idle window")
        (t/is (= session/default-cookie-max-age-absolute
                 (get-in expanded [:app.http.session.tasks/gc
                                   :app.http.session.tasks/max-age-absolute]))
              "task max-age-absolute should fall back to the default absolute cap")))))

(t/deftest session-gc-rejects-absolute-below-idle
  (let [pool   (:app.db/pool th/*system*)
        params {:app.db/pool pool
                :app.http.session.tasks/max-age (ct/duration {:days 7})
                :app.http.session.tasks/max-age-absolute (ct/duration {:days 30})}]
    (t/is (nil? (ig/assert-key :app.http.session.tasks/gc params))
          "absolute cap above the idle window should pass")
    (t/is (nil? (ig/assert-key :app.http.session.tasks/gc
                               (assoc params
                                      :app.http.session.tasks/max-age-absolute
                                      (ct/duration {:days 7}))))
          "absolute cap equal to the idle window should pass")
    (t/is (thrown? IllegalArgumentException
                   (ig/assert-key :app.http.session.tasks/gc
                                  (assoc params
                                         :app.http.session.tasks/max-age-absolute
                                         (ct/duration {:days 3}))))
          "absolute cap below the idle window should fail fast")))

(t/deftest idle-expired-session-is-rejected
  (let [cfg      th/*system*
        profile  (th/create-profile* 1)
        updated? (atom false)
        session  {:id          (uuid/random)
                  :profile-id  (:id profile)
                  :user-agent  "user agent"
                  :created-at  (ct/now)
                  :modified-at (ct/minus (ct/now) (ct/duration {:days 8}))}
        manager  (reify session/ISessionManager
                   (read-session [_ _] session)
                   (create-session [_ _] session)
                   (update-session [_ s] (reset! updated? true) s)
                   (delete-session [_ _] nil))
        token    (:token (#'session/assign-token cfg session))
        handler  (-> (fn [req] req)
                     (#'session/wrap-authz (assoc cfg ::session/manager manager))
                     (#'mw/wrap-auth {:bearer (partial session/decode-token cfg)
                                      :cookie (partial session/decode-token cfg)}))
        cookie-r (handler (th/make-dummy-request {:cookies {"auth-token" token}}))
        bearer-r (handler (th/make-dummy-request {:headers {"authorization" (str "Bearer " token)}}))]
    (t/is (nil? (::session/profile-id cookie-r))
          "idle-expired session must not authenticate via cookie")
    (t/is (nil? (::session/session cookie-r))
          "idle-expired session must not be attached via cookie")
    (t/is (nil? (::session/profile-id bearer-r))
          "idle-expired session must not authenticate via bearer")
    (t/is (false? @updated?)
          "idle-expired session must not be renewed")))

(t/deftest idle-session-within-window-is-accepted
  (let [cfg     th/*system*
        profile (th/create-profile* 1)
        session {:id          (uuid/random)
                 :profile-id  (:id profile)
                 :user-agent  "user agent"
                 :created-at  (ct/now)
                 :modified-at (ct/minus (ct/now) (ct/duration {:days 6}))}
        manager (reify session/ISessionManager
                  (read-session [_ _] session)
                  (create-session [_ _] session)
                  (update-session [_ s] (assoc s :modified-at (ct/now)))
                  (delete-session [_ _] nil))
        token   (:token (#'session/assign-token cfg session))
        handler (-> (fn [req] req)
                    (#'session/wrap-authz (assoc cfg ::session/manager manager))
                    (#'mw/wrap-auth {:bearer (partial session/decode-token cfg)
                                     :cookie (partial session/decode-token cfg)}))
        response (handler (th/make-dummy-request {:cookies {"auth-token" token}}))]
    (t/is (= (:id profile) (::session/profile-id response))
          "session within the idle window must authenticate")))

(t/deftest parse-request-illegal-argument-exception
  ;; clojure.data.json raises IllegalArgumentException (case
  ;; fall-through) on several kinds of malformed input. The
  ;; parse-request middleware should convert any such IAE into a
  ;; 400 :malformed-json validation error rather than letting it
  ;; surface as a 500 internal error. Because the conversion is
  ;; done by raising an ex-info (caught by the top-level error
  ;; handler in app.http/router-handler), this test asserts on
  ;; the ex-info thrown by wrap-parse-request directly.
  (let [handler (#'app.http.middleware/wrap-parse-request
                 (fn [_] {::yres/status 200 ::yres/body :ok})
                 (th/metrics-stub))
        ;; Body contains the bytes for: {"x": "\}"}  -- a string
        ;; value with a backslash followed by '}', which
        ;; clojure.data.json v0.5.x cannot handle.
        body    (.getBytes "{\"x\": \"\\}\"}" "UTF-8")
        request (th/make-dummy-request
                 {:method  :post
                  :headers {"content-type" "application/json"}
                  :body-bytes body})
        ex      (try
                  (handler request)
                  (catch clojure.lang.ExceptionInfo e e))]
    (t/is (instance? clojure.lang.ExceptionInfo ex))
    (t/is (= :validation (-> ex ex-data :type)))
    (t/is (= :malformed-json (-> ex ex-data :code)))
    (t/is (= "invalid JSON in request body" (-> ex ex-data :hint)))))

(defn- malformed-requests-count
  "Value of the malformed-body counter of a metrics instance."
  [metrics]
  (.getSampleValue ^CollectorRegistry (mtx/get-registry metrics)
                   "penpot_http_malformed_requests_total"
                   (make-array String 0)
                   (make-array String 0)))

(t/deftest parse-request-malformed-json-body
  ;; The body shape seen in production: an object where the parser expects a
  ;; key. clojure.data.json signals it with a bare java.lang.Exception, which
  ;; the class-based classification did not recognize, so it surfaced as a 500
  ;; :unexpected with the whole stack trace in the log. It is a client error:
  ;; 400 :malformed-json, and it is counted.
  (let [metrics (ig/init-key :app.metrics/metrics {:default main/default-metrics})
        handler (#'app.http.middleware/wrap-parse-request
                 (fn [_] {::yres/status 200 ::yres/body :ok})
                 metrics)
        request (th/make-dummy-request
                 {:method  :post
                  :headers {"content-type" "application/json"}
                  :body-bytes (.getBytes "{\"events\":[{{\"a\":1}:\"b\"}]}" "UTF-8")})
        ex      (try
                  (handler request)
                  (catch clojure.lang.ExceptionInfo e e))]
    (t/is (instance? clojure.lang.ExceptionInfo ex))
    (t/is (= :validation (-> ex ex-data :type)))
    (t/is (= :malformed-json (-> ex ex-data :code)))
    (t/is (= 1.0 (malformed-requests-count metrics)))))

(t/deftest parse-request-request-too-big-exception
  ;; When RequestTooBigException is raised (e.g. the request body
  ;; exceeded the configured size limit), the middleware should
  ;; convert it to a 413 :request-body-too-large validation
  ;; error.
  (let [handler (#'app.http.middleware/wrap-parse-request
                 (fn [_] (throw (RequestTooBigException. "too large")))
                 (th/metrics-stub))
        request (th/make-dummy-request
                 {:method  :post
                  :headers {"content-type" "application/json"}
                  :body-bytes (.getBytes "{}" "UTF-8")})
        ex      (try
                  (handler request)
                  (catch clojure.lang.ExceptionInfo e e))]
    (t/is (instance? clojure.lang.ExceptionInfo ex))
    (t/is (= :validation (-> ex ex-data :type)))
    (t/is (= :request-body-too-large (-> ex ex-data :code)))
    (t/is (= "request body exceeds size limit" (-> ex ex-data :hint)))))

(t/deftest parse-request-eof-exception
  ;; When java.io.EOFException is raised (e.g. the body stream
  ;; was closed before the parser could read it), the middleware
  ;; should convert it to a 400 :malformed-json validation error.
  (let [handler (#'app.http.middleware/wrap-parse-request
                 (fn [_] (throw (java.io.EOFException. "stream closed")))
                 (th/metrics-stub))
        request (th/make-dummy-request
                 {:method  :post
                  :headers {"content-type" "application/json"}
                  :body-bytes (.getBytes "{}" "UTF-8")})
        ex      (try
                  (handler request)
                  (catch clojure.lang.ExceptionInfo e e))]
    (t/is (instance? clojure.lang.ExceptionInfo ex))
    (t/is (= :validation (-> ex ex-data :type)))
    (t/is (= :malformed-json (-> ex ex-data :code)))
    (t/is (= "unexpected end of request body" (-> ex ex-data :hint)))))

(t/deftest parse-request-runtime-exception-with-cause
  ;; When a RuntimeException with a non-nil ex-cause is raised,
  ;; the middleware should recurse on the cause and dispatch
  ;; through the specific-exception branches. Here we wrap an
  ;; IllegalArgumentException in a RuntimeException and verify
  ;; it surfaces as :malformed-json.
  (let [iae     (IllegalArgumentException. "No matching clause: 99")
        wrapped (doto (RuntimeException. "wrapped")
                  (.initCause iae))
        handler (#'app.http.middleware/wrap-parse-request
                 (fn [_] (throw wrapped))
                 (th/metrics-stub))
        request (th/make-dummy-request
                 {:method  :post
                  :headers {"content-type" "application/json"}
                  :body-bytes (.getBytes "{}" "UTF-8")})
        ex      (try
                  (handler request)
                  (catch clojure.lang.ExceptionInfo e e))]
    (t/is (instance? clojure.lang.ExceptionInfo ex))
    (t/is (= :validation (-> ex ex-data :type)))
    (t/is (= :malformed-json (-> ex ex-data :code)))))

(t/deftest parse-request-runtime-exception-without-cause
  ;; When a bare RuntimeException (no ex-cause) is raised, the
  ;; middleware should fall through to errors/handle's :default
  ;; path and return a 500 with :type :server-error :code
  ;; :unexpected. This is the "true internal error" path.
  (let [handler  (#'app.http.middleware/wrap-parse-request
                  (fn [_] (throw (RuntimeException. "boom")))
                  (th/metrics-stub))
        request  (th/make-dummy-request
                  {:method  :post
                   :headers {"content-type" "application/json"}
                   :body-bytes (.getBytes "{}" "UTF-8")})
        response (handler request)
        body     (::yres/body response)]
    (t/is (= 500 (::yres/status response)))
    (t/is (= :server-error (:type body)))
    (t/is (= :unexpected (:code body)))
    (t/is (nil? (:hint body)))))

(t/deftest parse-request-non-runtime-throwable
  ;; When a non-RuntimeException Throwable is raised (e.g. an
  ;; Error subclass or a non-RuntimeException checked-style
  ;; exception), the middleware should fall through to the
  ;; :else branch and call errors/handle. java.io.IOException
  ;; has a dedicated handle-exception method that returns 500
  ;; with :code :io-exception.
  (let [handler  (#'app.http.middleware/wrap-parse-request
                  (fn [_] (throw (java.io.IOException. "network gone")))
                  (th/metrics-stub))
        request  (th/make-dummy-request
                  {:method  :post
                   :headers {"content-type" "application/json"}
                   :body-bytes (.getBytes "{}" "UTF-8")})
        response (handler request)
        body     (::yres/body response)]
    (t/is (= 500 (::yres/status response)))
    (t/is (= :server-error (:type body)))
    (t/is (= :io-exception (:code body)))
    (t/is (nil? (:hint body)))))

(t/deftest internal-error-strips-sensitive-fields
  ;; When an :internal error is raised with :state, :path, and
  ;; :context, those fields must not appear in the response body.
  ;; :hint is part of the error protocol and is preserved.
  (let [cause    (ex-info "internal error"
                          {:type :internal
                           :code :test-error
                           :hint "safe user-facing hint"
                           :state "XX000"
                           :path "/data/penpot/storage"
                           :context {:backend :s3 :bucket "prod"}})
        response (http-errors/handle cause {})
        body     (::yres/body response)]
    (t/is (= 500 (::yres/status response)))
    (t/is (= :server-error (:type body)))
    (t/is (= :test-error (:code body)))
    (t/is (= "safe user-facing hint" (:hint body)))
    (t/is (nil? (:state body)))
    (t/is (nil? (:path body)))
    (t/is (nil? (:context body)))))

(t/deftest unhandled-exinfo-strips-sensitive-fields
  ;; When an ex-info with an unregistered :type (dispatches through
  ;; handle-exception :default :else) carries :state and :path,
  ;; those fields must not appear in the response body.
  ;; :hint is part of the error protocol and is preserved.
  (let [cause    (ex-info "something broke"
                          {:type :unregistered-type
                           :code :custom-code
                           :hint "safe user-facing hint"
                           :state "internal-state"
                           :path "/internal/path"})
        response (http-errors/handle cause {})
        body     (::yres/body response)]
    (t/is (= 500 (::yres/status response)))
    (t/is (= :server-error (:type body)))
    (t/is (= :custom-code (:code body)))
    (t/is (= "safe user-facing hint" (:hint body)))
    (t/is (nil? (:state body)))
    (t/is (nil? (:path body)))))

(t/deftest validation-error-body-with-raw-explain-is-json-serializable
  ;; A :validation error whose ex-data carries the raw malli explain
  ;; (storage invalid-storage-metadata) must produce a response body
  ;; that survives JSON encoding. Before the fix the live schema
  ;; object inside the explain broke the writer mid-stream and the
  ;; client received a truncated body.
  (let [cause    (try
                   (stsch/encode-metadata {})
                   (catch clojure.lang.ExceptionInfo cause cause))
        response (http-errors/handle cause {})
        body     (::yres/body response)]
    (t/is (= 400 (::yres/status response)))
    (t/is (= :validation (:type body)))
    (t/is (= :invalid-storage-metadata (:code body)))
    (t/is (nil? (:app.common.schema/explain body)))
    (let [encoded (json/encode body :key-fn json/write-camel-key)
          decoded (json/decode encoded :key-fn json/read-kebab-key)]
      (t/is (str/includes? encoded "invalid-storage-metadata"))
      (t/is (string? (:explain decoded))))))
