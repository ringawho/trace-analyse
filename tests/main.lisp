(defpackage trace-analyse/tests/main
  (:use :cl
        :trace-analyse
        :rove))
(in-package :trace-analyse/tests/main)

;; NOTE: To run this test file, execute `(asdf:test-system :trace-analyse)' in your Lisp.

(defmethod ms:class-persistant-slots ((self trace-analyse::instruction))
  ;; don't persistant trace
  '(trace-analyse::offset
    trace-analyse::insn
    trace-analyse::prev
    trace-analyse::next
    trace-analyse::mark-type))

(defmethod instruction-equal (insn1 insn2)
  (loop for k in '(trace-analyse::offset
                   trace-analyse::insn-value
                   trace-analyse::prev
                   trace-analyse::next
                   trace-analyse::mark-type)
        always (equal (funcall k insn1)
                      (funcall k insn2))))

(defun set-equal (expr1 expr2)
  (and (set-difference expr1 expr2 :test 'equal)
       (set-difference expr2 expr1 :test 'equal)))

(defun hash-table-equal (expected result)
  (and (every (lambda (k)
                (instruction-equal (gethash k expected)
                                   (gethash k result)))
              (alexandria:hash-table-keys expected))
       (equal (alexandria:hash-table-keys expected)
              (alexandria:hash-table-keys result))))

;; test data-flow function with single instruction which has complex rizin il
(deftest instruction-data-flow
  (testing "Data flow"
    (let ((expr1 (trace-analyse::data-flow '(:SEQ (:STOREW 0 (:+ (:VAR :SP) (:BV 64 64)) (:VAR :X20))
                                             (:STOREW 0 (:+ (:+ (:VAR :SP) (:BV 64 64)) (:BV 64 8)) (:VAR :X19)))))
          (expr2 (trace-analyse::data-flow '(:SET :SP (:- (:VAR :SP) (:BV 64 416))))))
      (ok (set-equal (trace-analyse::data-dependency expr1 expr2)
                     '(:FROM (:X20 :X19)
                       :TO ((:+ (:VAR :SP) (:BV 64 64))
                            (:+ (:+ (:VAR :SP) (:BV 64 64)) (:BV 64 8))))))
      (ok (set-equal (trace-analyse::data-merge expr1 expr2)
                     '(:FROM (:X20 :X19 :SP)
                       :TO ((:SP)
                            (:+ (:VAR :SP) (:BV 64 64))
                            (:+ (:+ (:VAR :SP) (:BV 64 64)) (:BV 64 8)))))))))

(deftest test-target-1
  (testing "should (= 1 1) to be true"
    (ok (= 1 1))))

(deftest test-output-cfg
  (testing ""
    (multiple-value-bind (returned-links returned-group-nodes)
        (trace-analyse::output-cfg "resources/libAPSE_8.0.0.so" "resources/output-10e414-first.txt" :need-mark-vmp t)
      (let* ((links (ms:unmarshal (read-from-string (uiop:read-file-string "tests/suit/links.dat"))))
             (group-nodes (ms:unmarshal (read-from-string (uiop:read-file-string "tests/suit/group-nodes.dat")))))
        ;; (format t "~s~%" (ms:marshal returned-links))
        (ok (hash-table-equal links returned-links) "Links should match")
        (ok (equal group-nodes (reverse (mapcar #'trace-analyse::insn-lst returned-group-nodes))) "Group nodes should match")))))
