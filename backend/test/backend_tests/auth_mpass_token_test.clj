;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/.
;;
;; Copyright (c) KALEIDOS INC

(ns backend-tests.auth-mpass-token-test
  (:require
   [app.auth.mpass-token :as mpass-token]
   [backend-tests.mpass-tokens :as tk]
   [clojure.test :as t]))

(defn- verify
  ([token] (verify (tk/make-verifier) token))
  ([verifier token] (mpass-token/verify verifier token)))

(defn- reason
  [& args]
  (:reason (apply verify args)))

(t/deftest valid-access-token-is-verified
  (let [{:keys [claims reason]} (verify (tk/sign (tk/access-claims)))]
    (t/is (nil? reason))
    (t/is (= "mpass-user-1" (:sub claims)))
    (t/is (= tk/corporate-id (get claims (keyword "custom:corporate_id"))))))

(t/deftest valid-id-token-is-verified-with-string-or-list-audience
  (t/is (some? (:claims (verify (tk/sign (tk/id-claims))))))
  (t/is (some? (:claims (verify (tk/sign (tk/id-claims :aud ["other" tk/client-id])))))))

(t/deftest proxy-reissued-id-token-is-verified-against-its-own-jwks
  (let [claims (tk/id-claims :iss tk/proxy-issuer)]
    (t/is (some? (:claims (verify (tk/sign claims tk/proxy-key-pair)))))
    (t/is (= "bad_signature" (reason (tk/sign claims tk/signing-key-pair))))))

(t/deftest token-signed-by-another-key-is-rejected
  (t/is (= "bad_signature" (reason (tk/sign (tk/access-claims) tk/attacker-key-pair)))))

(t/deftest tampered-payload-is-rejected
  (let [token   (tk/sign (tk/access-claims (keyword "custom:corporate_id") "other-corp"))
        [h _ s] (.split ^String token "\\.")
        [_ p _] (.split ^String (tk/sign (tk/access-claims)) "\\.")]
    (t/is (= "bad_signature" (reason (str h "." p "." s))))))

(t/deftest expired-token-is-rejected-outside-the-leeway
  (t/is (= "expired" (reason (tk/sign (tk/access-claims :exp (- (tk/now-seconds) 120))))))
  (t/is (some? (:claims (verify (tk/sign (tk/access-claims :exp (- (tk/now-seconds) 30))))))))

(t/deftest untrusted-issuer-is-rejected-without-fetching
  (let [{:keys [calls fetch]} (tk/counting-fetcher)
        verifier              (tk/make-verifier :fetch fetch)]
    (t/is (= "untrusted_issuer"
             (reason verifier (tk/sign (tk/access-claims :iss "https://evil.example")))))
    (t/is (= 0 @calls))))

(t/deftest wrong-audience-is-rejected
  (t/is (= "wrong_audience" (reason (tk/sign (tk/access-claims :client_id "another-client")))))
  (t/is (= "wrong_audience" (reason (tk/sign (tk/id-claims :aud "another-client")))))
  (t/is (= "wrong_audience" (reason (tk/sign (tk/access-claims :token_use "refresh"))))))

(t/deftest non-rs256-algorithms-are-rejected
  (t/is (= "invalid" (reason (tk/unsigned-token (tk/access-claims)))))
  (t/is (= "invalid" (reason (tk/hs256-token (tk/access-claims))))))

(t/deftest required-claims-must-be-present
  (doseq [claim [:exp :iat :token_use]]
    (t/is (= "invalid" (reason (tk/sign (dissoc (tk/access-claims) claim))))
          (str "missing " claim))))

(t/deftest malformed-tokens-are-rejected
  (doseq [token ["" "abc" "a.b" "a.b.c" "x.y.z.w"]]
    (t/is (= "malformed" (reason token)) token)))

(t/deftest unknown-signing-key-is-rejected
  (let [verifier (tk/make-verifier :fetch (constantly {"other-kid" (.getPublic tk/signing-key-pair)}))]
    (t/is (= "unknown_signing_key" (reason verifier (tk/sign (tk/access-claims)))))))

(t/deftest unconfigured-verifier-rejects-everything
  (let [verifier (mpass-token/make-verifier {:issuers [] :client-id tk/client-id :fetch-jwks (constantly {})})]
    (t/is (= "verifier_unconfigured" (reason verifier (tk/sign (tk/access-claims))))))
  (let [verifier (mpass-token/make-verifier {:issuers [tk/cognito-issuer] :client-id "CHANGE_ME_CLIENT" :fetch-jwks (constantly {})})]
    (t/is (= "verifier_unconfigured" (reason verifier (tk/sign (tk/access-claims)))))))

(t/deftest jwks-is-cached-per-issuer
  (let [{:keys [calls fetch]} (tk/counting-fetcher)
        verifier              (tk/make-verifier :fetch fetch)]
    (dotimes [_ 3]
      (t/is (some? (:claims (verify verifier (tk/sign (tk/access-claims)))))))
    (t/is (= 1 @calls))
    (verify verifier (tk/sign (tk/id-claims :iss tk/proxy-issuer) tk/proxy-key-pair))
    (t/is (= 2 @calls))))

(t/deftest jwks-failure-rejects-and-backs-off-per-issuer
  (let [now                   (atom 1000000)
        {:keys [calls fetch]} (tk/counting-fetcher {tk/proxy-issuer (get tk/jwks-by-issuer tk/proxy-issuer)})
        verifier              (tk/make-verifier :fetch fetch :clock #(deref now))
        cognito-token         (tk/sign (tk/access-claims))]
    (t/is (= "jwks_unavailable" (reason verifier cognito-token)))
    (t/is (= "jwks_unavailable" (reason verifier cognito-token)))
    (t/is (= 1 @calls) "no refetch inside the backoff window")
    (t/is (some? (:claims (verify verifier (tk/sign (tk/id-claims :iss tk/proxy-issuer) tk/proxy-key-pair))))
          "another issuer is unaffected")
    (swap! now + mpass-token/jwks-failure-backoff-ms)
    (t/is (= "jwks_unavailable" (reason verifier cognito-token)))
    (t/is (= 3 @calls) "refetched once the backoff elapsed")))

(t/deftest jwks-parse-errors-are-unavailable-not-thrown
  (let [verifier (tk/make-verifier :fetch (fn [_] (throw (ex-info "bad json" {}))))]
    (t/is (= "jwks_unavailable" (reason verifier (tk/sign (tk/access-claims)))))))

(t/deftest jwks-keys-skips-unusable-entries
  (let [parsed (mpass-token/jwks->keys
                {:keys [(first (:keys (tk/jwks tk/signing-key-pair)))
                        {:kid "ec" :kty "EC" :crv "P-256" :x "x" :y "y"}
                        {:kid "broken" :kty "RSA" :n "!!" :e "!!"}
                        {:kty "RSA"}]})]
    (t/is (= #{tk/kid} (set (keys parsed))))))

(t/deftest issuers-from-config
  (t/is (= "https://issuer.example"
           (mpass-token/cognito-issuer-from-config {:mpass-cognito-issuer-url " https://issuer.example/ "})))
  (t/is (= "https://cognito-idp.eu-west-1.amazonaws.com/pool"
           (mpass-token/cognito-issuer-from-config {:mpass-cognito-issuer-url "CHANGE_ME_ISSUER"
                                                    :cognito-aws-region "eu-west-1"
                                                    :cognito-user-pool-id "pool"})))
  (t/is (nil? (mpass-token/cognito-issuer-from-config {:cognito-aws-region "eu-west-1"})))
  (t/is (nil? (mpass-token/token-issuer-from-config {:mpass-token-issuer-url "CHANGE_ME_"})))
  (t/is (= "https://issuer.example/.well-known/jwks.json"
           (mpass-token/jwks-url "https://issuer.example/"))))

(t/deftest verified-tokens-are-remembered-until-they-expire
  (let [now      (atom (System/currentTimeMillis))
        {:keys [calls fetch]} (tk/counting-fetcher)
        verifier (tk/make-verifier :fetch fetch :clock #(deref now))
        exp      (+ (quot @now 1000) 120)
        token    (tk/sign (tk/access-claims :exp exp))]
    (t/is (some? (:claims (verify verifier token))))
    (reset! (::mpass-token/state verifier) {:jwks {} :failed-at {tk/cognito-issuer @now}})
    (t/is (some? (:claims (verify verifier token))) "served from the verified cache")
    (t/is (= 1 @calls))
    (reset! now (* 1000 (+ exp 120)))
    (t/is (= "expired" (reason verifier token)) "re-verified once past exp")))

(t/deftest failed-verifications-are-not-remembered
  (let [verifier (tk/make-verifier)
        token    (tk/sign (tk/access-claims) tk/attacker-key-pair)]
    (t/is (= "bad_signature" (reason verifier token)))
    (t/is (empty? @(::mpass-token/verified verifier)))))

(t/deftest verified-cache-is-bounded
  (let [verifier (mpass-token/make-verifier {:issuers [tk/cognito-issuer]
                                             :client-id tk/client-id
                                             :fetch-jwks (:fetch (tk/counting-fetcher))
                                             :max-verified 3})]
    (doseq [n (range 10)]
      (t/is (some? (:claims (verify verifier (tk/sign (tk/access-claims :sub (str "user-" n)))))))
      (t/is (<= (count @(::mpass-token/verified verifier)) 3)))))

(t/deftest last-good-jwks-is-served-for-a-day-after-refresh-failures
  (let [now      (atom 1000000000)
        healthy? (atom true)
        calls    (atom 0)
        fetch    (fn [issuer]
                   (swap! calls inc)
                   (if @healthy?
                     (get tk/jwks-by-issuer issuer)
                     (throw (java.net.SocketTimeoutException. "timed out"))))
        verifier (tk/make-verifier :fetch fetch :clock #(deref now))
        fresh    #(tk/sign (tk/access-claims :sub (str (random-uuid))
                                             :iat (quot @now 1000)
                                             :exp (+ (quot @now 1000) 3600)))]
    (t/is (some? (:claims (verify verifier (fresh)))))
    (reset! healthy? false)
    (swap! now + mpass-token/jwks-lifespan-ms)
    (t/is (some? (:claims (verify verifier (fresh)))) "stale set served after a failed refresh")
    (t/is (= 2 @calls))
    (t/is (some? (:claims (verify verifier (fresh)))) "stale set served during the backoff")
    (t/is (= 2 @calls) "no fetch inside the backoff window")
    (swap! now + (- mpass-token/jwks-stale-max-ms mpass-token/jwks-lifespan-ms))
    (t/is (= "jwks_unavailable" (reason verifier (fresh))) "older than a day")
    (reset! healthy? true)
    (swap! now + mpass-token/jwks-failure-backoff-ms)
    (t/is (some? (:claims (verify verifier (fresh)))) "recovers once the IdP answers")))

(t/deftest one-jwks-fetch-in-flight-per-issuer
  (let [calls    (atom 0)
        fetch    (fn [issuer]
                   (swap! calls inc)
                   (Thread/sleep 200)
                   (get tk/jwks-by-issuer issuer))
        verifier (tk/make-verifier :fetch fetch)
        results  (->> (range 8)
                      (map (fn [n] (future (verify verifier (tk/sign (tk/access-claims :sub (str "u" n)))))))
                      (doall)
                      (map deref))]
    (t/is (every? :claims results))
    (t/is (= 1 @calls))))
