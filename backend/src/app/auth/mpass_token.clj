;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/.
;;
;; Copyright (c) KALEIDOS INC

(ns app.auth.mpass-token
  "Verifies the mPass token oauth2-proxy forwards in
  X-Auth-Request-Access-Token.

  A browser session forwards the Cognito access token; a Bearer caller
  forwards its id_token, which mpass-auth-proxy re-signs under its own
  issuer when email capture is on. Both issuers are trusted, each
  against its own JWKS, and nothing else is.

  `verify` returns `{:claims claims}` or `{:reason code}`; it never
  throws."
  (:require
   [app.common.exceptions :as ex]
   [app.common.logging :as l]
   [app.util.json :as json]
   [buddy.sign.jwk :as jwk]
   [buddy.sign.jwt :as jwt]
   [cuerdas.core :as str]
   [java-http-clj.core :as http])
  (:import
   java.nio.charset.StandardCharsets
   java.util.Base64))

(set! *warn-on-reflection* true)

(def jwks-lifespan-ms (* 60 60 1000))
(def jwks-fetch-timeout-ms 2000)
(def jwks-failure-backoff-ms (* 30 1000))
(def unknown-kid-refresh-ms (* 30 1000))
(def clock-skew-leeway-seconds 60)
(def required-claims [:exp :iat :iss :token_use])

(def ^:private placeholder-prefix "CHANGE_ME_")

(def ^:private validation-reasons
  {:exp "expired"
   :iss "untrusted_issuer"
   :signature "bad_signature"})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; CONFIGURATION
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn configured
  "A setting's value, or nil when it is unset, blank or still an
  .env.example placeholder."
  [value]
  (let [text (some-> value str/trim)]
    (when-not (or (str/blank? text)
                  (str/starts-with? text placeholder-prefix))
      text)))

(defn- issuer-url
  [value]
  (some-> (configured value) (str/rtrim "/") not-empty))

(defn cognito-issuer
  [region pool-id]
  (let [region  (configured region)
        pool-id (configured pool-id)]
    (when (and region pool-id)
      (str "https://cognito-idp." region ".amazonaws.com/" pool-id))))

(defn cognito-issuer-from-config
  "The Cognito issuer oauth2-proxy validates, falling back to the
  region and user pool pair."
  [config]
  (or (issuer-url (:mpass-cognito-issuer-url config))
      (cognito-issuer (:cognito-aws-region config)
                      (:cognito-user-pool-id config))))

(defn token-issuer-from-config
  [config]
  (issuer-url (:mpass-token-issuer-url config)))

(defn jwks-url
  [issuer]
  (str (str/rtrim issuer "/") "/.well-known/jwks.json"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; JWKS
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- rsa-entry
  [{:keys [kid kty] :as jwk-data}]
  (when (and (string? kid) (= "RSA" kty))
    (let [pkey (ex/try! (jwk/public-key jwk-data))]
      (when-not (ex/exception? pkey)
        [kid pkey]))))

(defn jwks->keys
  "Maps each usable RSA key's kid to its public key, skipping keys that
  cannot be used for RS256."
  [jwks]
  (into {} (keep rsa-entry) (:keys jwks)))

(defn- build-http-client
  []
  (http/build-client {:connect-timeout jwks-fetch-timeout-ms
                      :follow-redirects :never}))

(defn http-jwks-fetcher
  "A function of issuer returning its keys by kid; throws on any fetch
  or parse failure."
  ([] (http-jwks-fetcher (build-http-client)))
  ([client]
   (fn [issuer]
     (let [{:keys [status body]} (http/send {:method :get
                                             :uri (jwks-url issuer)
                                             :timeout jwks-fetch-timeout-ms}
                                            {:client client :as :string})]
       (when-not (= 200 status)
         (throw (ex-info "unexpected JWKS response status" {:status status})))
       (jwks->keys (json/decode body))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; VERIFIER
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn make-verifier
  [{:keys [issuers client-id fetch-jwks clock]
    :or {clock #(System/currentTimeMillis)}}]
  {::issuers (into #{} (keep issuer-url) issuers)
   ::client-id (configured client-id)
   ::fetch-jwks fetch-jwks
   ::clock clock
   ::state (atom {:jwks {} :failed-at {}})})

(defn verifier-from-config
  [config]
  (make-verifier {:issuers [(cognito-issuer-from-config config)
                            (token-issuer-from-config config)]
                  :client-id (:mpass-oidc-client-id config)
                  :fetch-jwks (http-jwks-fetcher)}))

(defn configured?
  [{:keys [::issuers ::client-id]}]
  (boolean (and (seq issuers) client-id)))

(defn audience-matches?
  "Cognito access tokens name the client in `client_id`; id_tokens in `aud`."
  [claims client-id]
  (case (:token_use claims)
    "access" (= client-id (:client_id claims))
    "id"     (let [aud (:aud claims)]
               (boolean (some #{client-id} (if (sequential? aud) aud [aud]))))
    false))

(defn- reject
  [reason]
  {:reason reason})

(defn- decode-segment
  [^String segment]
  (-> (.decode (Base64/getUrlDecoder) segment)
      (String. StandardCharsets/UTF_8)
      (json/decode)))

(defn- unverified-parts
  [^String token]
  (let [segments (.split token "\\." -1)]
    (when (= 3 (alength segments))
      (let [header (ex/try! (decode-segment (aget segments 0)))
            claims (ex/try! (decode-segment (aget segments 1)))]
        (when (and (map? header) (map? claims))
          {:header header :claims claims})))))

(defn- now-ms
  [{:keys [::clock]}]
  (clock))

(defn- recently-failed?
  [state issuer now]
  (when-let [failed-at (get-in state [:failed-at issuer])]
    (< (- now failed-at) jwks-failure-backoff-ms)))

(defn- fresh-entry
  [state issuer now]
  (let [{:keys [fetched-at] :as entry} (get-in state [:jwks issuer])]
    (when (and entry (< (- now fetched-at) jwks-lifespan-ms))
      entry)))

(defn- refresh-jwks!
  [{:keys [::fetch-jwks ::state]} issuer now]
  (try
    (let [entry {:keys (fetch-jwks issuer) :fetched-at now}]
      (swap! state assoc-in [:jwks issuer] entry)
      entry)
    (catch Throwable cause
      (l/wrn :hint "mpass token: unable to fetch JWKS"
             :issuer issuer
             :cause (ex-message cause))
      (swap! state assoc-in [:failed-at issuer] now)
      nil)))

(defn- may-refresh-for-unknown-kid?
  [entry kid now]
  (and (not (contains? (:keys entry) kid))
       (>= (- now (:fetched-at entry)) unknown-kid-refresh-ms)))

(defn- signing-key
  [verifier issuer kid]
  (let [now   (now-ms verifier)
        state @(::state verifier)]
    (if (recently-failed? state issuer now)
      (reject "jwks_unavailable")
      (let [entry (or (fresh-entry state issuer now)
                      (refresh-jwks! verifier issuer now))
            entry (if (and entry (may-refresh-for-unknown-kid? entry kid now))
                    (refresh-jwks! verifier issuer now)
                    entry)]
        (cond
          (nil? entry)                (reject "jwks_unavailable")
          (get-in entry [:keys kid])  {:key (get-in entry [:keys kid])}
          :else                       (reject "unknown_signing_key"))))))

(defn- unsign
  [verifier token pkey issuer]
  (try
    {:claims (jwt/unsign token pkey {:alg :rs256
                                     :iss issuer
                                     :leeway clock-skew-leeway-seconds
                                     :now (quot (long (now-ms verifier)) 1000)})}
    (catch clojure.lang.ExceptionInfo cause
      (reject (get validation-reasons (:cause (ex-data cause)) "invalid")))
    (catch Throwable _
      (reject "invalid"))))

(defn- missing-required-claim?
  [claims]
  (some #(nil? (get claims %)) required-claims))

(defn- check-claims
  [verifier claims]
  (cond
    (missing-required-claim? claims)
    (reject "invalid")

    (not (audience-matches? claims (::client-id verifier)))
    (reject "wrong_audience")

    :else
    {:claims claims}))

(defn- verify-signed
  [verifier token {:keys [header claims]}]
  (let [issuer (:iss claims)
        found  (signing-key verifier issuer (:kid header))]
    (if (:reason found)
      found
      (let [result (unsign verifier token (:key found) issuer)]
        (if (:reason result)
          result
          (check-claims verifier (:claims result)))))))

(defn verify
  [verifier token]
  (let [parts (when (string? token) (unverified-parts token))]
    (cond
      (not (configured? verifier))
      (reject "verifier_unconfigured")

      (nil? parts)
      (reject "malformed")

      (not (contains? (::issuers verifier) (-> parts :claims :iss)))
      (reject "untrusted_issuer")

      (not= "RS256" (-> parts :header :alg))
      (reject "invalid")

      :else
      (verify-signed verifier token parts))))
