;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/.
;;
;; Copyright (c) KALEIDOS INC

(ns backend-tests.http-middleware-test
  (:require
   [app.common.time :as ct]
   [app.config :as cf]
   [app.db :as db]
   [app.http :as-alias http]
   [app.http.access-token :as access-token]
   [app.http.auth-request]
   [app.http.middleware :as mw]
   [app.http.session :as session]
   [app.main :as-alias main]
   [app.rpc :as-alias rpc]
   [app.rpc.commands.access-token]
   [app.rpc.commands.profile :as profile]
   [app.tokens :as tokens]
   [backend-tests.helpers :as th]
   [clojure.test :as t]
   [mockery.core :refer [with-mocks]]
   [yetti.request :as yreq]
   [yetti.response :as yres]))

(t/use-fixtures :once th/state-init)
(t/use-fixtures :each th/database-reset)

(defrecord DummyRequest [headers cookies]
  yreq/IRequestCookies
  (get-cookie [_ name]
    {:value (get cookies name)})

  yreq/IRequest
  (get-header [_ name]
    (get headers name)))

(t/deftest auth-middleware-1
  (let [request (volatile! nil)
        handler (#'app.http.middleware/wrap-auth
                 (fn [req] (vreset! request req))
                 {})]

    (handler (->DummyRequest {} {}))

    (t/is (nil? (::http/auth-data @request)))

    (handler (->DummyRequest {"authorization" "Token aaaa"} {}))

    (let [{:keys [token claims] token-type :type} (get @request ::http/auth-data)]
      (t/is (= :token token-type))
      (t/is (= "aaaa" token))
      (t/is (nil? claims)))))

(t/deftest auth-middleware-2
  (let [request (volatile! nil)
        handler (#'app.http.middleware/wrap-auth
                 (fn [req] (vreset! request req))
                 {})]

    (handler (->DummyRequest {} {}))
    (t/is (nil? (::http/auth-data @request)))

    (handler (->DummyRequest {"authorization" "Bearer aaaa"} {}))

    (let [{:keys [token claims] token-type :type} (get @request ::http/auth-data)]
      (t/is (= :bearer token-type))
      (t/is (= "aaaa" token))
      (t/is (nil? claims)))))

(t/deftest auth-middleware-3
  (let [request (volatile! nil)
        handler (#'app.http.middleware/wrap-auth
                 (fn [req] (vreset! request req))
                 {})]

    (handler (->DummyRequest {} {}))
    (t/is (nil? (::http/auth-data @request)))

    (handler (->DummyRequest {} {"auth-token" "foobar"}))

    (let [{:keys [token claims] token-type :type} (get @request ::http/auth-data)]
      (t/is (= :cookie token-type))
      (t/is (= "foobar" token))
      (t/is (nil? claims)))))

(t/deftest shared-key-auth
  (let [handler (#'app.http.middleware/wrap-shared-key-auth
                 (fn [req] {::yres/status 200})
                 {:test1 "secret-key"})]

    (let [response (handler (->DummyRequest {} {}))]
      (t/is (= 403 (::yres/status response))))

    (let [response (handler (->DummyRequest {"x-shared-key" "secret-key2"} {}))]
      (t/is (= 403 (::yres/status response))))

    (let [response (handler (->DummyRequest {"x-shared-key" "secret-key"} {}))]
      (t/is (= 403 (::yres/status response))))

    (let [response (handler (->DummyRequest {"x-shared-key" "test1 secret-key"} {}))]
      (t/is (= 200 (::yres/status response))))))

(t/deftest access-token-authz
  (let [profile (th/create-profile* 1)
        token   (db/tx-run! th/*system* app.rpc.commands.access-token/create-access-token (:id profile) "test" nil)
        handler (#'app.http.access-token/wrap-authz identity th/*system*)]

    (let [response (handler nil)]
      (t/is (nil? response)))

    (let [response (handler {::http/auth-data {:type :token :token "foobar" :claims {:tid (:id token)}}})]
      (t/is (= #{} (:app.http.access-token/perms response)))
      (t/is (= (:id profile) (:app.http.access-token/profile-id response))))))

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

        response (handler (->DummyRequest {} {"auth-token" (:token session)}))

        {:keys [token claims] token-type :type}
        (get response ::http/auth-data)]

    (t/is (= :cookie token-type))
    (t/is (= (:token session) token))
    (t/is (= "authentication" (:iss claims)))
    (t/is (= "penpot" (:aud claims)))
    (t/is (= (:id session) (:sid claims)))
    (t/is (= (:id profile) (:uid claims)))))

(t/deftest session-authz-does-not-renew-on-error-response
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
                    (handler (->DummyRequest {} {"auth-token" (:token token)})))]
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
    (handler (->DummyRequest {} {}))
    (t/is (nil? (::session/profile-id @captured)))))

(t/deftest x-auth-request-drops-local-session-when-header-email-unresolvable
  ;; When wrap-session has resolved alice's profile-id from the local
  ;; auth-token cookie, and the proxy header asserts an email that does
  ;; NOT resolve to a Penpot profile (unknown upstream user + auto-register
  ;; off), the middleware MUST drop alice's session-pid before calling
  ;; the downstream handler. The upstream identity has changed; continuing
  ;; to serve alice would leak her data to whoever is now upstream.
  ;;
  ;; Per openspec proxy-auth-middleware Rule 2: "Identity mismatch SHALL
  ;; flush the existing session immediately", even when we cannot re-key
  ;; to a known new identity.
  (let [profile-id   (random-uuid)
        stale-session {:id (random-uuid) :profile-id profile-id}
        captured     (volatile! nil)
        handler      (#'app.http.auth-request/wrap-authz
                      (fn [req] (vreset! captured req) req)
                      (make-xauth-cfg))
        request      (-> (->DummyRequest {"x-auth-request-email" "user@example.com"} {})
                         (assoc ::session/profile-id profile-id)
                         (assoc ::session/session stale-session))
        response     (handler request)]
    ;; Downstream handler must NOT see alice's profile-id.
    (t/is (nil? (::session/profile-id @captured)))
    ;; Downstream handler must NOT see alice's stale local session.
    (t/is (nil? (::session/session @captured)))
    ;; Browser cookie is explicitly expired.
    (t/is (= 0 (get-in response [::yres/cookies "auth-token" :max-age])))))

(t/deftest x-auth-request-preserves-local-session-when-profile-lookup-errors
  (let [profile-id    (random-uuid)
        stale-session {:id (random-uuid) :profile-id profile-id}
        captured      (volatile! nil)
        handler       (#'app.http.auth-request/wrap-authz
                       (fn [req] (vreset! captured req) req)
                       (make-xauth-cfg))
        request       (-> (->DummyRequest {"x-auth-request-email" "user@example.com"} {})
                          (assoc ::session/profile-id profile-id)
                          (assoc ::session/session stale-session))
        response      (with-redefs [app.http.auth-request/get-or-register-profile
                                    (fn [& _]
                                      (throw (ex-info "db down" {})))]
                        (handler request))]
    ;; Operational errors should not be treated as "unknown user" and
    ;; destructively clear local session state.
    (t/is (= profile-id (::session/profile-id @captured)))
    (t/is (= stale-session (::session/session @captured)))
    (t/is (not (contains? (::yres/cookies response) "auth-token")))))

(t/deftest x-auth-request-rekeys-when-session-identity-differs
  ;; Repro of the QA-reported bug: alice's auth-token cookie persists on
  ;; Penpot's subdomain after the portal "log out of all apps"; bob then
  ;; logs in upstream. wrap-session resolves alice's profile-id from the
  ;; old cookie, but oauth2-proxy is forwarding bob's email. The middleware
  ;; must re-key to bob.
  (let [alice    (th/create-profile* 1 {:is-active true})
        bob      (th/create-profile* 2 {:is-active true})
        captured (volatile! nil)
        cfg      (make-xauth-cfg)
        handler  (#'app.http.auth-request/wrap-authz
                  (fn [req] (vreset! captured req) {::yres/status 200})
                  cfg)
        request  (-> (->DummyRequest {"x-auth-request-email" (:email bob)} {})
                     (assoc ::session/profile-id (:id alice))
                     (assoc ::session/session {:id (random-uuid)
                                               :profile-id (:id alice)}))
        response (handler request)]
    ;; Downstream handler sees bob's profile-id, not alice's.
    (t/is (= (:id bob) (::session/profile-id @captured)))
    ;; Stale local session object is removed before downstream handling.
    (t/is (nil? (::session/session @captured)))
    ;; A fresh auth-token cookie is issued for bob's session.
    (t/is (contains? (::yres/cookies response) "auth-token"))))

(t/deftest x-auth-request-no-rekey-when-session-matches-header
  ;; Steady-state: the browser session matches the proxy identity. No
  ;; re-key, no new cookie — the session passes through cleanly. This
  ;; guards against issuing a fresh cookie on every authenticated request.
  (let [profile  (th/create-profile* 1 {:is-active true})
        captured (volatile! nil)
        cfg      (make-xauth-cfg)
        handler  (#'app.http.auth-request/wrap-authz
                  (fn [req] (vreset! captured req) {::yres/status 200})
                  cfg)
        request  (-> (->DummyRequest {"x-auth-request-email" (:email profile)} {})
                     (assoc ::session/profile-id (:id profile)))
        response (handler request)]
    (t/is (= (:id profile) (::session/profile-id @captured)))
    ;; No new auth-token cookie when the session already matches.
    (t/is (not (contains? (::yres/cookies response) "auth-token")))))

(t/deftest x-auth-request-rekey-not-overwritten-by-session-renewal
  ;; Integration guard: session/authz wraps x-auth-request and can renew the
  ;; incoming cookie after inner middleware returns. Ensure bob's re-keyed
  ;; cookie wins even when renewal is forced.
  (let [alice          (th/create-profile* 1 {:is-active true})
        bob            (th/create-profile* 2 {:is-active true})
        cfg            (make-xauth-cfg)
        t0             (ct/inst "2025-01-01T00:00:00Z")
        t1             (ct/plus t0 (ct/duration {:seconds 2}))
        ;; Keep this lower than (t1 - t0) so the stale incoming session is
        ;; always considered due for renewal in this test.
        renewal-threshold (ct/duration {:seconds 1})
        middleware     (-> (fn [req] {::yres/status 200
                                       :seen-profile-id (::session/profile-id req)})
                           (#'app.http.auth-request/wrap-authz cfg)
                           (#'session/wrap-authz cfg)
                           (#'mw/wrap-auth {:bearer (partial session/decode-token cfg)
                                            :cookie (partial session/decode-token cfg)}))
        seeded-token   (binding [ct/*clock* (ct/fixed-clock t0)]
                         (get-in ((session/create-fn cfg alice)
                                  (->DummyRequest {} {})
                                  {::yres/status 200})
                                 [::yres/cookies "auth-token" :value]))
        response       (binding [cf/config (assoc cf/config
                                                  ;; Renewal is triggered once elapsed age exceeds
                                                  ;; this threshold.
                                                  :auth-token-cookie-renewal-max-age
                                                  renewal-threshold)
                                 ct/*clock* (ct/fixed-clock t1)]
                         (middleware (->DummyRequest {"x-auth-request-email" (:email bob)}
                                                     {"auth-token" seeded-token})))
        rekeyed-token  (get-in response [::yres/cookies "auth-token" :value])
        followup       (middleware (->DummyRequest {} {"auth-token" rekeyed-token}))]
    (t/is (neg? (compare renewal-threshold (ct/diff t0 t1))))
    (t/is (some? rekeyed-token))
    (t/is (not= seeded-token rekeyed-token))
    (t/is (= (:id bob) (:seen-profile-id response)))
    (t/is (= (:id bob) (:seen-profile-id followup)))))

(t/deftest x-auth-request-skips-when-access-token-present
  (let [profile-id (random-uuid)
        handler    (#'app.http.auth-request/wrap-authz
                    (fn [req] req)
                    (make-xauth-cfg))
        request    (-> (->DummyRequest {"x-auth-request-email" "user@example.com"} {})
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
        response (handler (->DummyRequest {"x-auth-request-email" (:email profile)} {}))]
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
        response (handler (->DummyRequest {"x-auth-request-email" (:email profile)} {}))]
    (t/is (= 403 (::yres/status response)))))

(t/deftest x-auth-request-inactive-profile-returns-403
  (let [profile  (th/create-profile* 3 {:is-active false})
        handler  (#'app.http.auth-request/wrap-authz
                  (fn [_] {::yres/status 200})
                  (make-xauth-cfg))
        response (handler (->DummyRequest {"x-auth-request-email" (:email profile)} {}))]
    (t/is (= 403 (::yres/status response)))))

(t/deftest x-auth-request-unknown-email-no-autoregister
  (let [captured (volatile! nil)
        handler  (#'app.http.auth-request/wrap-authz
                  (fn [req] (vreset! captured req) {::yres/status 200})
                  (make-xauth-cfg))]
    (handler (->DummyRequest {"x-auth-request-email" "nobody@example.com"} {}))
    (t/is (nil? (::session/profile-id @captured)))))

(t/deftest x-auth-request-auto-register-creates-active-profile
  (binding [cf/flags (conj cf/flags :x-auth-request-auto-register)]
    (let [email    "newuser@example.com"
          fullname "New User"
          captured (volatile! nil)
          cfg      (make-xauth-cfg)
          handler  (#'app.http.auth-request/wrap-authz
                    (fn [req] (vreset! captured req) {::yres/status 200})
                    cfg)
          response (handler (->DummyRequest {"x-auth-request-email" email
                                             "x-auth-request-user"  fullname} {}))]
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
        (t/is (= (::session/profile-id @captured) (:id profile)))))))
