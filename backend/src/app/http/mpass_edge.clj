;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/.
;;
;; Copyright (c) KALEIDOS INC

(ns app.http.mpass-edge
  "Decides whether a request came through the Traefik SSO router.

  Traefik sets X-Mpass-Edge-Secret on the router that runs mPass
  ForwardAuth. Without a usable secret a direct call on the backend
  network is indistinguishable from one that passed ForwardAuth, so an
  unusable secret trusts nothing."
  (:require
   [yetti.request :as yreq])
  (:import
   java.nio.charset.StandardCharsets
   java.security.MessageDigest))

(set! *warn-on-reflection* true)

(def header "x-mpass-edge-secret")

(def min-secret-length 32)

(defn usable-secret?
  [secret]
  (and (string? secret)
       (>= (count secret) min-secret-length)))

(defn- utf8-bytes
  ^bytes [^String s]
  (.getBytes s StandardCharsets/UTF_8))

(defn from-edge?
  [request secret]
  (and (usable-secret? secret)
       (MessageDigest/isEqual (utf8-bytes secret)
                              (utf8-bytes (or (yreq/get-header request header) "")))))
