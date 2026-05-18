;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/.
;;
;; Copyright (c) KALEIDOS INC

(ns backend-tests.http-portal-logout-test
  "Unit tests for the ?next= allowlist in the portal-logout endpoint.

  These cover the pure-function `allowed-next?` predicate. The handler
  itself is exercised via integration in the FOSS bundle: with a real
  session it 302s + clears the cookie, with a rejected next= it 200s +
  clears the cookie. Verified manually against the devstack."
  (:require
   [app.config :as cf]
   [app.http.portal-logout :as plg]
   [clojure.test :as t]))

(defmacro with-platform-domain
  [domain & body]
  `(with-redefs [cf/get (fn [k# & [default#]]
                          (if (= k# :platform-domain) ~domain default#))]
     ~@body))

(t/deftest allowed-next-host-equals-platform-domain
  (with-platform-domain "foss.arbisoft.com"
    (t/is (true? (#'plg/allowed-next? "https://foss.arbisoft.com/")))))

(t/deftest allowed-next-host-is-subdomain
  (with-platform-domain "foss.arbisoft.com"
    (t/is (true? (#'plg/allowed-next? "https://pm.foss.arbisoft.com/done")))
    (t/is (true? (#'plg/allowed-next? "https://docs.foss.arbisoft.com/x")))))

(t/deftest allowed-next-rejects-other-host
  (with-platform-domain "foss.arbisoft.com"
    (t/is (false? (#'plg/allowed-next? "https://evil.example/steal")))))

(t/deftest allowed-next-enforces-dot-boundary
  ;; Suffix match without dot boundary would let foss.arbisoft.com.evil
  ;; pass as a "subdomain" of foss.arbisoft.com. The endpoint must
  ;; refuse this.
  (with-platform-domain "foss.arbisoft.com"
    (t/is (false? (#'plg/allowed-next? "https://foss.arbisoft.com.evil/x")))))

(t/deftest allowed-next-rejects-non-http-scheme
  ;; javascript:, data:, mailto: parse fine as URIs but must never be
  ;; honoured as redirect targets.
  (with-platform-domain "foss.arbisoft.com"
    (t/is (false? (#'plg/allowed-next?
                   "javascript:alert(document.cookie)")))
    (t/is (false? (#'plg/allowed-next?
                   "data:text/html,<script>alert(1)</script>")))))

(t/deftest allowed-next-rejects-everything-when-platform-domain-unset
  (with-platform-domain nil
    (t/is (false? (#'plg/allowed-next? "https://foss.arbisoft.com/"))))
  (with-platform-domain ""
    (t/is (false? (#'plg/allowed-next? "https://foss.arbisoft.com/")))))

(t/deftest allowed-next-rejects-malformed-url
  (with-platform-domain "foss.arbisoft.com"
    (t/is (false? (#'plg/allowed-next? ":::garbage")))
    (t/is (false? (#'plg/allowed-next? "not-a-url")))))

(t/deftest allowed-next-normalises-platform-domain
  ;; Operators sometimes write ".foss.arbisoft.com" (leading dot) — the
  ;; predicate should treat that as the same domain.
  (with-platform-domain ".foss.arbisoft.com"
    (t/is (true? (#'plg/allowed-next? "https://pm.foss.arbisoft.com/")))
    (t/is (false? (#'plg/allowed-next? "https://foss.arbisoft.com.evil/")))))
