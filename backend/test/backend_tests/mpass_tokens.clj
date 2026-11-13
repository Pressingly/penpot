;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/.
;;
;; Copyright (c) KALEIDOS INC

(ns backend-tests.mpass-tokens
  "Signing keys, tokens and a counting JWKS fetcher for mPass token tests."
  (:require
   [app.auth.mpass-token :as mpass-token]
   [app.util.json :as json]
   [buddy.core.codecs :as bc]
   [buddy.core.keys :as bk]
   [buddy.sign.jwt :as jwt])
  (:import
   java.security.KeyPairGenerator))

(def cognito-issuer "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_TestPool")
(def proxy-issuer "https://auth-proxy.test")
(def client-id "test-client-id")
(def corporate-id "corp-123")
(def kid "test-kid")

(defn- generate-key-pair
  []
  (.generateKeyPair (doto (KeyPairGenerator/getInstance "RSA")
                      (.initialize 2048))))

(def signing-key-pair (generate-key-pair))
(def proxy-key-pair (generate-key-pair))
(def attacker-key-pair (generate-key-pair))

(defn jwks
  [key-pair]
  {:keys [(assoc (bk/public-key->jwk (.getPublic ^java.security.KeyPair key-pair))
                 :kid kid :alg "RS256" :use "sig")]})

(def jwks-by-issuer
  {cognito-issuer (mpass-token/jwks->keys (jwks signing-key-pair))
   proxy-issuer   (mpass-token/jwks->keys (jwks proxy-key-pair))})

(defn now-seconds
  []
  (quot (System/currentTimeMillis) 1000))

(defn access-claims
  [& {:as overrides}]
  (merge {:iss cognito-issuer
          :sub "mpass-user-1"
          :token_use "access"
          :client_id client-id
          :iat (now-seconds)
          :exp (+ (now-seconds) 3600)
          (keyword "custom:is_corporate") "true"
          (keyword "custom:corporate_id") corporate-id}
         overrides))

(defn id-claims
  [& {:as overrides}]
  (merge (access-claims :token_use "id" :client_id nil :aud client-id)
         overrides))

(defn sign
  ([claims] (sign claims signing-key-pair))
  ([claims key-pair]
   (jwt/sign (into {} (remove (comp nil? val)) claims)
             (.getPrivate ^java.security.KeyPair key-pair)
             {:alg :rs256 :header {:kid kid}})))

(defn- b64url
  [data]
  (-> (json/encode data) (bc/bytes->b64 true) bc/bytes->str))

(defn unsigned-token
  [claims]
  (str (b64url {:alg "none" :kid kid}) "." (b64url claims) "."))

(defn hs256-token
  [claims]
  (jwt/sign claims "a-shared-secret-an-attacker-picked" {:alg :hs256 :header {:kid kid}}))

(defn counting-fetcher
  "A JWKS fetcher serving `keys-by-issuer` and counting its calls; an
  issuer it does not know fails like an unreachable endpoint."
  ([] (counting-fetcher jwks-by-issuer))
  ([keys-by-issuer]
   (let [calls (atom 0)]
     {:calls calls
      :fetch (fn [issuer]
               (swap! calls inc)
               (or (get keys-by-issuer issuer)
                   (throw (java.net.ConnectException. "connection refused"))))})))

(defn make-verifier
  [& {:keys [fetch clock issuers]
      :or {issuers [cognito-issuer proxy-issuer]}}]
  (mpass-token/make-verifier (cond-> {:issuers issuers
                                      :client-id client-id
                                      :fetch-jwks (or fetch (:fetch (counting-fetcher)))}
                               clock (assoc :clock clock))))
