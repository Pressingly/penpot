;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/.
;;
;; Copyright (c) KALEIDOS SUBSIDIARY SL

(ns common-tests.flags-test
  (:require
   [app.common.flags :as flags]
   [clojure.test :as t]))

(t/deftest admin-console-is-disabled-by-default
  (t/is (not (contains? (flags/parse flags/default) :admin-console))))

(t/deftest enable-admin-console-flag-turns-it-on
  (t/is (contains? (flags/parse flags/default [:enable-admin-console]) :admin-console)))

(t/deftest disable-admin-console-flag-keeps-it-off
  (t/is (not (contains? (flags/parse flags/default [:disable-admin-console]) :admin-console))))
