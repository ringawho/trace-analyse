(defpackage trace-analyse/tests/main
  (:use :cl
        :trace-analyse
        :rove))
(in-package :trace-analyse/tests/main)

;; NOTE: To run this test file, execute `(asdf:test-system :trace-analyse)' in your Lisp.

(deftest test-target-1
  (testing "should (= 1 1) to be true"
    (ok (= 1 1))))
