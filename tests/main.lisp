(defpackage trace-analyse/tests/main
  (:use :cl
        :trace-analyse
        :rove))
(in-package :trace-analyse/tests/main)

;; NOTE: To run this test file, execute `(asdf:test-system :trace-analyse)' in your Lisp.

(defun hash-table-equal (expected result)
  (and (every (lambda (k)
                (equal (gethash k expected)
                       (gethash k result)))
              (alexandria:hash-table-keys expected))
       (equal (alexandria:hash-table-keys expected)
              (alexandria:hash-table-keys result))))

(deftest test-target-1
  (testing "should (= 1 1) to be true"
    (ok (= 1 1))))

(deftest test-output-cfg
  (testing ""
    (multiple-value-bind (returned-links returned-group-nodes)
        (trace-analyse::output-cfg "resources/libAPSE_8.0.0.so" "resources/output-10e414-first.txt" :need-mark-vmp t)
      (let* ((links (ms:unmarshal (read-from-string (uiop:read-file-string "tests/suit/links.dat"))))
             (group-nodes (ms:unmarshal (read-from-string (uiop:read-file-string "tests/suit/group-nodes.dat")))))
        (ok (hash-table-equal links returned-links) "Links should match")
        (ok (equal group-nodes returned-group-nodes) "Group nodes should match")))))
