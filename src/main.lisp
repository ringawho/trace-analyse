(uiop:define-package trace-analyse
  (:use #:cl)
  (:export #:main))
(in-package #:trace-analyse)

(defparameter *rizin* nil)

(defun get-offset-and-insn (insn)
  (destructuring-bind (offset insn) (cl-ppcre:split " " insn :limit 2)
    (values (parse-integer offset :start 2 :radix 16)
            insn)))

(defun diff-alists (lst1 lst2)
  (if (or (null lst1) (null lst2))
      (or lst1 lst2)
      (loop for (key . val) in lst1
            when (equal val (cdr (assoc key lst2 :test 'equal)))
              collect (cons key val))))

(defun find-tree (node tree &key (test #'eql))
  (if (atom tree)
      (funcall test node tree)
      (or (funcall test node tree)
          (find-tree node (car tree) :test test)
          (find-tree node (cdr tree) :test test))))

(defclass instruction ()
  ((offset :initarg :offset :reader offset)
   (insn :initarg :insn :reader insn-value)
   (prev :initarg :prev :accessor prev :initform nil)
   (next :initarg :next :accessor next :initform nil)
   (mark-type :initarg :mark-type :accessor mark-type :initform nil)
   (trace :initarg :trace :accessor trace-value :initform nil)))

(defclass insn-nodes ()
  ((insn-lst :initarg :insn-lst :reader insn-lst)
   (vmp-insn-lst :initarg :vmp-insn-lst :accessor vmp-insn-lst :initform nil)
   (trace :initarg :trace :accessor common-trace :initform nil)))

(defun get-insn-info (trace-file)
  (with-open-file (stream trace-file :direction :input)
    (loop with insn-hash = (make-hash-table :test 'equal)
          and previous = nil
          and regs = nil
          for line = (read-line stream nil nil)
          while line
          when (cl-ppcre:scan "^\\s+\\{" line)
            do (setf regs (parse-trace-regs regs line))
          when (uiop:string-prefix-p "0x" line)
            do (unless (gethash line insn-hash)
                 (multiple-value-bind (offset insn) (get-offset-and-insn line)
                   ;; (format t "~s~%" line)
                   ;; (format t "         ~s~%         ~s~%" (rizin:il *rizin* :offset offset)
                   ;;         (data-flow (rizin:il *rizin* :offset offset)))
                   (setf (gethash line insn-hash)
                         (make-instance 'instruction :offset offset :insn insn))))
               (when previous
                 (pushnew line (next (gethash previous insn-hash)) :test 'equal)
                 (pushnew previous (prev (gethash line insn-hash)) :test 'equal))
               (let ((entry (gethash line insn-hash)))
                 (setf (trace-value entry)
                       (diff-alists (trace-value entry)
                                    (loop for k being the hash-key using (hash-value v) of regs
                                          collect (cons (intern (string-upcase k) :keyword) v)))))
               (setf previous line)
          finally (return insn-hash))))

(defun dependency-p (ele1 ele2)
  (or (equal ele1 ele2)
      (and (listp ele2)
           (equal (car ele2) :mem)
           (find-tree ele1 ele2))))

(defun data-dependency (flow1 flow2 &key (direction :forward))
  (let* ((flow1-from (getf flow1 :from))
         (flow1-to (getf flow1 :to))
         (flow2-from (getf flow2 :from))
         (flow2-to (getf flow2 :to))
         (affected (intersection flow1-to flow2-from :test 'dependency-p)))
    (case direction
      (:forward (values (list :from flow1-from
                              :to (if affected
                                      (union flow1-to flow2-to :test 'equal)
                                      (set-difference flow1-to flow2-to :test 'equal)))
                        affected))
      (:backward (values (list :from (if affected
                                         (union flow1-from (set-difference flow2-from flow1-to :test 'equal)
                                                :test 'equal)
                                         flow2-from)
                               :to flow2-to)
                         affected))
      (otherwise (error (format nil "Invalid direction: ~a, key must be :forward and :backward.~%" direction))))))

(defun data-merge (flow1 flow2)
  (list :from (union (getf flow1 :from)
                     (set-difference (getf flow2 :from) (getf flow1 :to) :test 'equal)
                     :test 'equal)
        :to (union (getf flow1 :to) (getf flow2 :to) :test 'equal)))

(defun parse-mem (expr)
  (list :mem
        (trivia:match expr
          ((list :+ (list :+ (list :var var) (list :bv bit1 value1))
                 (list :bv bit2 value2))
           (unless (= bit1 bit2)
             (error (format nil "Parse mem expr failed ~s, different bit width~%" expr)))
           `(:+ (:var ,var) (:bv ,bit1 ,(+ value1 value2))))
          ;; ((list :var _) expr)
          ;; ((list :+ (list :var _) (list :bv _ _)) expr)
          ;; ((list :+ (list :var _) (list :var _)) expr)
          ;; (_ (error (format nil "Parse mem expr failed ~s~%" expr)))
          (_ expr))))

(defun data-unit (expr)
  (trivia:match expr
    ((list :var reg) (uiop:ensure-list reg))
    ((list :bv _ _) nil)
    ((list :load _ mem) (list (parse-mem mem)))
    ((list :loadw _ _ mem) (list (parse-mem mem)))
    ((list :cast _ _ var) (data-unit var))
    ;; is same as data-merge, without final to
    ((list :let var value body) (union (data-unit value)
                                       (set-difference (data-unit body) (list var))))
    ((trivia:guard (list op value)
                   (member op '(:msb :is_zero :! :neg)))
     (data-unit value))
    ((trivia:guard (list op value1 value2)
                   (member op '(:+ :- :* :& :or :oror :^ :ule :&& :^^)))
     (append (data-unit value1)
             (data-unit value2)))
    ((trivia:guard (list op value1 value2 _)
                   (member op '(:>> :<<)))
     (append (data-unit value1)
             (data-unit value2)))
    (_ (error (format nil "Parse unit failed ~s~%" expr)))))

(defun data-flow (expr)
  ;; (format t "expr: ~S~%" expr)
  (trivia:match expr
    ((list :storew 0 mem from-expr) (list :from (data-unit from-expr) :to (list (parse-mem mem))))
    ((list :set reg from-expr) (list :from (data-unit from-expr) :to (list reg)))
    ((list :jmp target) (list :from (data-unit target)))
    ((list :branch cond b1 b2) (list :from (append (data-unit cond)
                                                   (getf (data-merge (data-flow b1) (data-flow b2)) :from))))

    ((list* :seq operands) (reduce #'data-merge
                                   (mapcar #'data-flow operands)))

    (:nop nil)
    (_ (error (format nil "Parse failed ~s~%" expr)))))

(defun insn-regs-read (expr)
  (loop for f in (trivia:match expr
                   ;; Example:
                   ;;   insn: 0x10fdd0 str x9, [x23]
                   ;;   data-flow (:from (:x9) :to (:mem (:var :x23)))
                   ;;   regs-read is '(:x9 :x23), is different with the :from of data-flow
                   ((list :storew 0 mem from-expr) (append (list (parse-mem mem)) (data-unit from-expr)))
                   (_ (getf (data-flow expr) :from)))
        append (if (and (listp f) (equal (car f) :mem))
                   (data-unit (cadr f))
                   (list f))))

(defun format-mem (expr context)
  (format nil "[~a]" (format-unit expr context)))

(defun format-reg (reg context)
  (destructuring-bind (hook base) context
    (if hook
        (let ((i (position reg hook)))
          (unless i
            (error (format nil "Format reg (~a) error~%" i)))
          (format nil "{~a}" (+ i base)))
        reg)))

(defun format-unit (expr context)
  (trivia:match expr
    ((list :var reg) (format-reg reg context))
    ((list :bv _ num) (format nil "0x~x" num))
    ((list :load _ mem) (format-mem mem context))
    ((list :loadw _ _ mem) (format-mem mem context))
    ((list :cast _ _ var) (format-unit var context))
    ;; is same as data-merge, without final to
    ;; ((list :let var value body) (union (format-unit value)
    ;;                                    (set-difference (format-unit body) (list var))))
    ((trivia:guard (list op value)
                   (member op '(:msb :is_zero :! :neg)))
     (format nil "~a ~a" op (format-unit value context)))
    ((trivia:guard (list op value1 value2)
                   (member op '(:+ :- :* :& :or :oror :^ :ule :&& :^^)))
     (format nil "~a ~a ~a" (format-unit value1 context) op (format-unit value2 context)))
    ((trivia:guard (list op value1 value2 _)
                   (member op '(:>> :<<)))
     (format nil "~a ~a ~a" (format-unit value1 context) op (format-unit value2 context)))
    (_ (error (format nil "Parse unit failed ~s~%" expr)))))

(defun format-il-to-equation (expr context &key lastp)
  (let ((to-context (cons (when lastp (car context))
                          (cdr context))))
    (trivia:match expr
      ((list :storew 0 mem from-expr)
       (list :from (format-unit from-expr context)
             :to (format-mem mem to-context)))
      ((list :set reg from-expr)
       (list :from (format-unit from-expr context) :to (format-reg reg to-context)))
      ;; ((list :jmp target) (list :from (format-unit target)))
      ;; ((list :branch cond b1 b2) (list :from (append (format-unit cond)
      ;;                                                (getf (data-merge (data-flow b1) (data-flow b2)) :from))))

      ;; ((list* :seq operands) (reduce #'data-merge
      ;;                                (mapcar #'data-flow operands)))

      ;; (:nop nil)
      (_ (error (format nil "Parse failed ~s~%" expr))))))

(defun valid-cmp (insn-hash k)
  "the k is cmp insn, return t if branch depends the result of cmp"
  (loop with cmp-entry = (gethash k insn-hash)
        with cmp-flow = (data-flow (rizin:il *rizin* :offset (offset cmp-entry)))
        ;; cmp hash only one next
        with cur = (car (next cmp-entry))

        while cur
        for entry = (gethash cur insn-hash)
        for flow = (data-flow (rizin:il *rizin* :offset (offset entry)))
        and nexts = (next entry)
        when (intersection (getf cmp-flow :to) (getf flow :to) :test 'equal)
          return nil
        when (and (intersection (getf cmp-flow :to) (getf flow :from) :test 'equal)
                  (> (length nexts) 1))
          return t
        do (setf cur (when (<= (length nexts) 1)
                       (car nexts)))))

(defun show-menu (title content)
  (format t "~%~{~8@a ~}~%" (cons "index" title))
  (format t "~&~{~{[~6@s]~@{ ~8@a~}~}~%~}"
          (loop for i from 0
                for item in content
                collect (cons i (uiop:ensure-list item)))))

(defun read-regs-from-user (default-index &key multi)
  (format t "Select regs (default=~a)~a: " default-index
          (if multi
              " (multi index need splited by comma or space)"
              ""))
  (finish-output)
  (let ((input (string-trim "" (read-line))))
    (if multi
        (uiop:ensure-list
         (if (string= input "")
             default-index
             (loop for index in (ppcre:split "\\s*,\\s*|\\s+" input)
                   collect (parse-integer index))))
        (if (string= input "")
            default-index
            (parse-integer input)))))

(defun get-op-regs (insn-hash &key (default-index 0 default-index-p))
  (let ((freq-hash (make-hash-table :test 'equal))
        op-regs)
    (loop for k being the hash-key using (hash-value v) of insn-hash
          when (search "cmp" k)
            do (let ((valid (valid-cmp insn-hash k))
                     (flow (data-flow (rizin:il *rizin* :offset (offset v)))))
                 (loop for reg in (getf flow :from)
                       for entry = (gethash reg freq-hash (list :insn nil :freq-times 0 :valid-times 0))
                       when valid
                         do (incf (getf entry :valid-times))
                       do (incf (getf entry :freq-times))
                          (pushnew k (getf entry :insn))
                          (setf (gethash reg freq-hash) entry))))
    (setf op-regs (sort (alexandria:hash-table-alist freq-hash)
                        (lambda (a b)
                          (let ((valid-a (getf (cdr a) :valid-times))
                                (valid-b (getf (cdr b) :valid-times))
                                (freq-a (getf (cdr a) :freq-times))
                                (freq-b (getf (cdr b) :freq-times)))
                            (or (> valid-a valid-b)
                                (and (= valid-a valid-b)
                                     (> freq-a freq-b)))))))
    (show-menu '("Reg" "Valid" "Freq")
               (loop for item in op-regs
                     collect (list (first item)
                                   (getf (cdr item) :valid-times)
                                   (getf (cdr item) :freq-times))))
    (let ((select-regs (loop for index in (if default-index-p
                                              default-index
                                              (read-regs-from-user default-index :multi t))
                             collect (nth index op-regs))))
      (format t "Selected regs are: ~{~a~^, ~}~%" (mapcar #'car select-regs))
      select-regs)))

(defun get-vmp-insn-mem (insn-hash regs &key (default-index 0 default-index-p))
  (loop for k in (loop for r in regs
                       append (getf (cdr r) :insn))
        for vmp-insn-mem = nil
        for cmp-entry = (gethash k insn-hash)
        for cmp-flow = (data-flow (rizin:il *rizin* :offset (offset cmp-entry)))
        and cmp-prev = (prev cmp-entry)
        when (= (length cmp-prev) 1)
          do (loop with acc-flow = cmp-flow     ; accumulator flow
                   with cur = (car cmp-prev)
                   while cur
                   for entry = (gethash cur insn-hash)
                   for flow = (data-flow (rizin:il *rizin* :offset (offset entry)))
                   and prev = (prev entry)
                   do (multiple-value-bind (new-flow affected) (data-dependency flow acc-flow :direction :backward)
                        (when (and affected
                                   (some (lambda (f)
                                           (and (listp f) (equal (car f) :mem)))
                                         (getf new-flow :from)))
                          (pushnew cur vmp-insn-mem :test 'equal))
                        (setf acc-flow new-flow))
                      (setf cur (when (= (length prev) 1)
                                  (car prev))))
        finally (show-menu '("" "instruction") vmp-insn-mem)
                (let ((select-insn (nth (if default-index-p
                                            default-index
                                            (read-regs-from-user default-index))
                                        vmp-insn-mem)))
                  (format t "Selected vmp insn mem is: ~a~%" select-insn)
                  (return select-insn))))

(defun mark-vmp-instruction (insn-hash from-insn
                             &key acc-flow
                               (visited (make-hash-table :test 'equal))
                               (is-first t))
  (loop with cur-insn = from-insn
        and cur-acc-flow = acc-flow
        and affected = nil
        ;; and show = nil

        while cur-insn
        for cur-flow = (data-flow (rizin:il *rizin* :offset (offset (gethash cur-insn insn-hash))))
        and cur-insn-visited = (gethash cur-insn visited)
        ;; do (when (uiop:string-prefix-p "0x10ed98" cur-insn)
        ;;      (setf show t))
        ;;    (when show
        ;;      (format t "special insn: ~a~%   ~a~%   ~a --- ~a~%" cur-insn cur-acc-flow cur-insn-visited
        ;;              (and cur-insn-visited
        ;;                   (subsetp (getf cur-acc-flow :from) (getf cur-insn-visited :from)))))
        if (and cur-insn-visited
                (subsetp (getf cur-acc-flow :from) (getf cur-insn-visited :from))
                (subsetp (getf cur-acc-flow :to) (getf cur-insn-visited :to)))
          do (setf cur-insn nil)
        else
          do (setf (gethash cur-insn visited)
                   (loop for key in '(:from :to)
                         append (list key (union (getf cur-acc-flow key) (getf cur-insn-visited key) :test 'equal))))
             (setf cur-acc-flow (gethash cur-insn visited))


             ;; (when (uiop:string-prefix-p "0x10eb40" cur-insn)
             ;;   (format t "0x10eb40 data flow: ~a~%   ~a~%   ~a~%~%" cur-acc-flow cur-flow (data-dependency cur-acc-flow cur-flow)))

             (multiple-value-setq (cur-acc-flow affected)
               (if (or (getf cur-acc-flow :from)
                       (getf cur-acc-flow :to))
                   (data-dependency cur-acc-flow cur-flow)
                   (values cur-flow t)))
             (when (or affected
                       (and (equal cur-insn from-insn) is-first))
               ;; (unless (mark-type (gethash cur-insn insn-hash))
               ;;   (format t "mark vmp insn new: ~a~%" cur-insn))
               (setf (mark-type (gethash cur-insn insn-hash)) t))
             (let ((nexts (next (gethash cur-insn insn-hash))))
               (setf cur-insn (car nexts))
               (loop for n in (cdr nexts)
                     do (mark-vmp-instruction insn-hash n :acc-flow cur-acc-flow :visited visited :is-first nil)))))

(defun parse-trace-regs (regs line)
  (let ((new-regs (com.inuoe.jzon:parse line)))
    (if regs
        (maphash (lambda (k v)
                   (let ((vals (cl-ppcre:split "\\s*=>\\s*" v)))
                     (unless (and (= 2 (length vals))
                                  (equal (first vals) (gethash k regs)))
                       (error (format nil "the length of vals is not equal 2, vals is ~s~%" vals)))
                     (setf (gethash k regs) (second vals))))
                 new-regs)
        ;; first need clear, only keep x0~x30
        (progn (maphash (lambda (k v)
                          (declare (ignore v))
                          (unless (uiop:string-prefix-p "x" k)
                            (remhash k new-regs)))
                        new-regs)
               (setf regs new-regs)))
    regs))

(defun merge-insn-nodes (insn-hash)
  (let ((visited (make-hash-table :test 'equal)))
    (flet ((merge-func (start-line &key collect
                        &aux (reverse-collect (if (equal collect #'next) #'prev #'next)))
             (loop with cur = start-line
                   while cur
                   when (not (gethash cur visited))
                     collect cur
                   do (setf (gethash cur visited) t)
                      (let ((lst (funcall collect (gethash cur insn-hash))))
                        (setf cur (if (and (= (length lst) 1)
                                           (= (length (funcall reverse-collect
                                                               (gethash (first lst) insn-hash)))
                                              1))
                                      (first lst)
                                      nil))))))
      (loop for line being the hash-key of insn-hash
            unless (gethash line visited)
              collect (make-instance 'insn-nodes
                                     :insn-lst (append (reverse (merge-func line :collect #'prev))
                                                       (merge-func line :collect #'next)))))))

(defun mark-vmp-insn-in-op (insn-hash vmp-insn regs)
  "Get common value trace, and get vmp-path in op path.

1. Find which is major op and which is minor op.
2. Get all vmp insn and op value in op path."
  (loop with pending = (list (list vmp-insn nil nil))
        and visited = (make-hash-table :test #'equal)
        and affected = nil
        and op-path-hash = (make-hash-table :test #'equal)

        while pending
        for (cur-insn flow first-cmp) = (pop pending)
        for entry = (gethash cur-insn insn-hash)
        for cur-flow = (data-flow (rizin:il *rizin* :offset (offset entry)))
        when (mark-type entry)
          do ;; if cur-insn is op cmp insn, then reg is op reg, else nil
             (let ((reg (loop for r in regs
                              for insns = (getf (cdr r) :insn)
                              when (member cur-insn insns :test #'equal)
                                return (car r))))
               ;; first-cmp is plist, key is reg, value is first cmp insn with this reg
               ;; if already has cmp-reg, current reg is subop
               ;; so need store cmp-reg value which exists as condition
               ;; Example: '(:X21 ("0x10e5f8 cmp w21, #0x27")
               ;;            :X24 ("0x10e6a8 cmp w24, #0x1b" (:X21 . "0x12")))
               (when (and reg
                          (not (getf first-cmp reg)))
                 (setf (getf first-cmp reg)
                       (cons cur-insn
                             (loop for (k v) on first-cmp by #'cddr   ; condition
                                   collect (assoc k (trace-value entry))))))

               ;; calc op cmp insn affected
               (when flow
                 (multiple-value-setq (flow affected) (data-dependency flow cur-flow)))
               ;; record op cmp insn
               (when reg
                 (setq flow cur-flow))

               ;; ensure cur-insn is in op path (all op reg value is fixed)
               (when (and (not reg)
                          (not affected)
                          first-cmp
                          (loop for (k v) on first-cmp by #'cddr
                                always (assoc k (trace-value entry))))
                 (let ((op-path (loop for (k v) on first-cmp by #'cddr
                                      for op-value = (cdr (assoc k (trace-value entry)))
                                      collect (list k op-value (car v)))))
                   (push cur-insn (gethash op-path
                                           op-path-hash)))))

        do (loop for n in (next entry)
                 unless (gethash n visited)
                   do (setf (gethash n visited) t)
                      (push (list n (copy-tree flow) (copy-tree first-cmp)) pending))
        finally (return op-path-hash)))

(defun generate-op-lst (insn-hash op-path-hash)
  (loop with nested-path-hash = (make-hash-table)
        for rk being the hash-key using (hash-value rv) of op-path-hash
        ;; key and value need reverse
        for k = (reverse rk)
        for v = (reverse rv)
        do (setf (gethash rk op-path-hash) v)
           (handler-case
               (let ((hook (generate-hook insn-hash v)))
                 (loop with cur-path-hash = nested-path-hash
                       for rest-op on k
                       for (op-reg op-value-str) = (car rest-op)
                       for op-value = (parse-integer op-value-str :start 2 :radix 16)
                       if (cdr rest-op)
                         do (unless (gethash op-value cur-path-hash)
                              (setf (gethash op-value cur-path-hash)
                                    (list :op (list op-value)
                                          :hook (list
                                                 (list :insn (offset (gethash (third (second rest-op)) insn-hash))
                                                       :reg (loop for r in (list (car (second rest-op)))
                                                                  collect (string-downcase (symbol-name r)))
                                                       :subop (make-hash-table))))))
                            (setf cur-path-hash
                                  (getf (car
                                         (getf (gethash op-value cur-path-hash)
                                               :hook))
                                        :subop))
                       else
                         do (setf (gethash op-value cur-path-hash)
                                  (list :op (list op-value)
                                        :hook (loop for h in (car hook)
                                                    collect (list :insn (car h)
                                                                  :reg (loop for r in (cadr h)
                                                                             collect (string-downcase (symbol-name r)))))
                                        :format (cadr hook)))))
             (error (e)
               (format t "~s~%~{~a~%~}" k v)
               (format t "Can not generate hook: ~%    ~a~%" e)))
        finally (format t "~a~%" (com.inuoe.jzon:stringify (convert-jzon-struct nested-path-hash)
                                                           :pretty t))))

(defun convert-jzon-struct (nested-path-hash)
  ;; 1. the op hash only keep value
  ;; 2. the op hash value need convert to hash-table
  ;; 3. each elements in the :hook of op hash value need convert to hash-table
  ;; 4. :subop of element need to call recursive
  (loop for k being the hash-key using (hash-value v) of nested-path-hash
        do (setf (getf v :hook)
                 (loop for h in (getf v :hook)
                       when (getf h :subop)
                         do (setf (getf h :subop)
                                  (convert-jzon-struct (getf h :subop)))
                       collect (alexandria:plist-hash-table h)))
        collect (alexandria:plist-hash-table v)))

(defun generate-hook (insn-hash v)
  (loop with equation-hash = (make-hash-table)
        ;; loop regs in one op-path
        for rest on v
        for line = (car rest)
        for lastp = (null (cdr rest))
        for entry = (gethash line insn-hash)
        for il = (rizin:il *rizin* :offset (offset entry))
        for regs-read = (insn-regs-read il)
        for equation = (format-il-to-equation il (list regs-read base) :lastp lastp)
        do (setf (gethash (getf equation :to) equation-hash)
                 (calc-new-equations equation-hash (getf equation :from) regs-read base))
           ;; (format t "stored equations: ~a ~s~%" line (gethash (getf equation :to) equation-hash))
        collect (list (offset entry) regs-read) into hook-lst
        sum (length regs-read) into base
        when lastp
          do (when (> (hash-table-count equation-hash) 1)
               (error "There is not only one out expression.~%"))
          and return (let ((last-to (getf equation :to)))
                       (list hook-lst
                             (format nil "~a~{ = ~a~}" last-to (gethash last-to equation-hash))))))

(defun calc-new-equations (equation-hash equation regs-read base)
  (loop with new-equations = (list equation)
        for i from base
        for r in regs-read
        when (gethash r equation-hash)
          do ;; (format t "new-equations: ~s ~s ~s~%" i new-equations (gethash r equation-hash))
             (setf new-equations (calc-new-equations-one-reg new-equations (gethash r equation-hash) i))
             (remhash r equation-hash)
             ;; (format t "new-equations-res: ~s~%" new-equations)
        finally (return new-equations)))

(defun calc-new-equations-one-reg (equations reg-equation i)
  (cons (car equations)
        (loop for index from 0 below (max (length (cdr equations))
                                          (length reg-equation))
              for expr-lst = (cdr equations) then (cdr expr-lst)
              for reg-expr-lst = reg-equation then (cdr reg-expr-lst)
              for expr = (or (car expr-lst) expr (car equations))
              for reg-expr = (or (car reg-expr-lst) reg-expr)
              ;; do (format t "replace one reg: ~s ~s ~s ~s~%" i expr reg-expr (cl-ppcre:regex-replace-all
              ;;                                                                (format nil "\\{~a\\}" i)
              ;;                                                                expr
              ;;                                                                reg-expr))
              collect (cl-ppcre:regex-replace-all
                       (format nil "\\{~a\\}" i)
                       expr
                       reg-expr))))

(defclass cfg ()
  ((insn-hash :initarg :links
              :accessor cfg-links)
   (nodes :initarg :nodes
          :accessor cfg-nodes)))

(defmethod cl-dot:graph-object-node ((graph cfg) (object insn-nodes))
  (let ((table-lines
          (append (loop for l in (common-trace object)
                        collect `(:tr ()
                                      (:td ((:align "left"))
                                           (:font ((:color "#ff0000"))
                                                  ,(format nil "~s~%" l)))))
                  (loop for line in (insn-lst object)
                        collect `(:tr ()
                                      (:td ((:align "left"))
                                           (:font ,(when (mark-type (gethash line (cfg-links graph)))
                                                     '((:color "#990073")))
                                                  ,line)))))))
    (make-instance 'cl-dot:node
                   :attributes `(:label
                                 (:html ()
                                        (:table ((:border "0"))
                                                ,@table-lines))
                                 ;; (:left ,(format nil "~{~a~%~}" object))
                                 ;; (list :left (format nil "~{~a~%~}" object))
                                 :style :filled
                                 :fontname "monospace"
                                 :shape :rect
                                 :style (:filled :rounded)
                                 :fillcolor "#eeeefa"))))

(defmethod cl-dot:graph-object-points-to ((graph cfg) (object insn-nodes))
  (mapcar (lambda (next)
            (find-if (lambda (area) (string= next (car (insn-lst area))))
                     (cfg-nodes graph)))
          (next (gethash (car (last (insn-lst object))) (cfg-links graph)))))

(defun output-cfg (so-file trace-file &key need-mark-vmp output-file)
  (setf *rizin* (rizin:rizin-open so-file))
  (let* ((insn-hash (get-insn-info trace-file))
         (group-nodes (merge-insn-nodes insn-hash)))
    (when need-mark-vmp
      (let* ((regs (get-op-regs insn-hash :default-index '(0 1)))
             (vmp-insn (get-vmp-insn-mem insn-hash regs :default-index 0)))
        (mark-vmp-instruction insn-hash vmp-insn)
        (generate-op-lst
         insn-hash
         (mark-vmp-insn-in-op insn-hash vmp-insn regs))))

    (when output-file
      (cl-dot:dot-graph
       (cl-dot:generate-graph-from-roots (make-instance 'cfg :links insn-hash :nodes group-nodes)
                                         group-nodes
                                         ;; :splines "ortho"
                                         '(:rankdir "TB"))
       output-file :format :svg))
    (rizin:quit *rizin*)

    (values insn-hash group-nodes)))

(defun main ()
  (output-cfg "resources/libAPSE_8.0.0.so" "resources/output-10e414-first.txt" :need-mark-vmp t :output-file "test-lr.svg")

  ;; (setf *rizin* (rizin:rizin-open "/home/ring/reverse_workspace/Happy_New_Year_2025_Challenge/problem3/lib/arm64-v8a/libnativelib.so"))
  ;; (output-cfg "/home/ring/reverse_workspace/Happy_New_Year_2025_Challenge/output.txt"
  ;;             :output-file "happy-new-year-problem.svg"
  ;;             :need-mark-vmp t)
  ;; (rizin:quit *rizin*)
  )
