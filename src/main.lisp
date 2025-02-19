(uiop:define-package trace-analyse
  (:use #:cl)
  (:export #:main))
(in-package #:trace-analyse)

(defparameter *rizin* nil)

(defmacro adjoin-plist-item (lst key item)
  `(setf (getf ,lst ,key)
         (adjoin ,item (getf ,lst ,key) :test 'equal)))

(defun get-ins-info (trace-file)
  (let ((links (make-hash-table :test 'equal))
        previous)
    (with-open-file (stream trace-file :direction :input)
      (loop for line = (read-line stream nil nil)
            while line
            when (uiop:string-prefix-p "0x" line)
              do (unless (gethash line links)
                   (setf (gethash line links) (list :prev nil :next nil :attr nil)))
                 (when previous
                   (let ((prev-entry (gethash previous links))
                         (curr-entry (gethash line links)))
                     (adjoin-plist-item prev-entry :next line)
                     (adjoin-plist-item curr-entry :prev previous)))
                 (setf previous line)
            finally (return links)))))

(defun merge-ins-block (links)
  (let ((visited (make-hash-table :test 'equal))
        areas)
    (maphash
     (lambda (line val)
       (declare (ignore val))
       (unless (gethash line visited)
         (let (area
               (cur line))
           (loop while cur
                 do (push cur area)
                    (setf (gethash cur visited) t)
                    (let ((prevs (getf (gethash cur links) :prev)))
                      (setf cur (if (and (= (length prevs) 1)
                                         (= (length (getf (gethash (first prevs) links) :next)) 1))
                                    (first prevs)
                                    nil))))
           (setf area (nreverse area))
           (pop area)
           (setf cur line)
           (loop while cur
                 do (push cur area)
                    (setf (gethash cur visited) t)
                    (let ((nexts (getf (gethash cur links) :next)))
                      (setf cur (if (and (= (length nexts) 1)
                                         (= (length (getf (gethash (first nexts) links) :prev)) 1))
                                    (first nexts)
                                    nil))))
           (push (nreverse area) areas))))
     links)
    areas))

(defun read-ins (so-filename)
  (with-open-file (stream so-filename
                          :direction :input
                          :element-type '(unsigned-byte 8))
    (let* ((size (file-length stream))
           (buffer (make-array size :element-type '(unsigned-byte 8))))
      (read-sequence buffer stream)
      buffer)))

(defun get-offset-and-isn (insn)
  (destructuring-bind (offset ins) (cl-ppcre:split " " insn :limit 2)
    (values (parse-integer offset :start 2 :radix 16)
            ins)))

(defun find-tree (node tree &key (test #'eql))
  (if (atom tree)
      (funcall test node tree)
      (or (funcall test node tree)
          (find-tree node (car tree) :test test)
          (find-tree node (cdr tree) :test test))))

(defun parse-rizinil (expr)
  (trivia:match expr
    ((list 'set reg value)
     (list 'set reg (parse-rizinil value)))
    ((list 'storew _ to value)
     (list 'set (parse-rizinil to) (parse-rizinil value)))

    ;; unwrap
    ((list 'loadw _ _ value)
     (list 'mem (parse-rizinil value)))
    ((list 'load _ value)
     (list 'mem (parse-rizinil value)))
    ((list 'var value) value)
    ((list 'msb value) value)
    ((list 'is_zero value) (list 'zerop (parse-rizinil value)))
    ((list '! value) (list '! (parse-rizinil value)))
    ((list 'neg value) (list 'neg (parse-rizinil value)))
    ((list 'not value) (list 'not (parse-rizinil value)))
    ((list 'bv _ value) value)
    ((list 'cast bit-num _ value)
     (if (= bit-num 64)
         (parse-rizinil value)
         (list 'cast bit-num (parse-rizinil value))))

    ;; unused
    ((list 'jmp offset) (list 'jump (parse-rizinil offset)))
    ('nop nil)
    ((list 'branch condition true-branch false-branch)
     (list 'branch (parse-rizinil condition)
           (parse-rizinil true-branch) (parse-rizinil false-branch)))

    ((list 'ite condition true-branch false-branch)
     (list 'ite (parse-rizinil condition)
           (parse-rizinil true-branch) (parse-rizinil false-branch)))

    ;; complex
    ((list* 'seq operands)
     (apply #'list 'seq (mapcar #'parse-rizinil operands)))
    ((list 'let var value body)
     (subst (parse-rizinil value)
            var
            (parse-rizinil body)
            :test 'equal))

    ;; calc
    ((trivia:guard (list* op value1 value2 _)
                   (member op '(+ - *
                                >> <<
                                & or ^ ule oror
                                && ^^)))
     (list op
           (parse-rizinil value1)
           (parse-rizinil value2)))
    (_ (error (format nil "Parse failed ~a~%" expr)))))

(defun get-rizinil (off)
  (parse-rizinil
   (read-from-string
    (reduce (lambda (res cur)
              (cl-ppcre:regex-replace-all (car cur) res (cdr cur)))
            '(("\\~-" . "neg") ("\\~" . "not") ("\\|"  . "or") ("0x"   . "#x"))
            :initial-value (nth-value 1 (get-offset-and-isn (rizin:il *rizin* :offset off)))))))

(defun mark-vmp-ins (origin-ins insn-mem insn-index cur-insn vmp-info expr)
  ;; (format t "vmp-info: ~a~%" vmp-info)
  ;; (format t "insn rizinil: ~a~%" expr)
  (let ((new-vmp-info (copy-tree vmp-info)))
    (labels ((exists-in-vmp-info (key operand)
               (find-if (lambda (known)
                          (find-tree known operand :test #'equal))
                        (getf vmp-info key)))
             (highlight-insn ()
               (adjoin-plist-item origin-ins :attr '(:color "#990073")))
             (highlight-and-update-vmp-info (key &rest operands)
               (highlight-insn)
               (dolist (op operands)
                 (adjoin-plist-item new-vmp-info key op)))
             (remove-vmp-info (key operand)
               (setf (getf new-vmp-info key)
                     (remove-if (lambda (known)
                                  (find-tree operand known :test #'equal))
                                (getf new-vmp-info key)))))
      (trivia:match expr
        ((list 'set operand1 operand2)
         (cond
           ((trivia:match operand2
              ((trivia:guard (list 'mem (list '+ base index))
                             (and (member base (getf vmp-info :insn-mem))
                                  (member index (getf vmp-info :insn-index))))
               t))
            (highlight-and-update-vmp-info :insn operand1 operand2))
           ((string= cur-insn insn-mem)
            (highlight-and-update-vmp-info :insn-mem operand1 operand2))
           ((string= cur-insn insn-index)
            (highlight-and-update-vmp-info :insn-index operand1 operand2))
           ;; operand1 will contain new value, so need remove old info about operand1
           ;; remove old, then add new
           (t (loop for key in '(:insn-mem :insn-index :insn :op)
                    do (when (exists-in-vmp-info key operand1)
                         (remove-vmp-info key operand1))
                       (when (exists-in-vmp-info key operand2)
                         (highlight-and-update-vmp-info key operand1 operand2))))))
        ((list* 'branch operand _)
         (when (find-tree operand vmp-info :test #'equal)
           (highlight-insn)))
        ((list* 'seq operands)
         ;; seq is multi expr, so need recursive call
         (loop for e in operands
               do (setf new-vmp-info
                        ;; new-vmp-info will update every il expr, so need use new-vmp-info
                        (mark-vmp-ins origin-ins insn-mem insn-index cur-insn new-vmp-info e))))))
    new-vmp-info))

(defun mark-vmp (links &key
                         ;; (insn-mem "0x194f0 and x12, x11, #0xffff")
                         ;; (vmp-info '(:insn-mem (x0) :insn-index () :insn () :op ()))
                         (insn-mem "0x10e51c ldr x8, [x19, #0x28]")
                         (insn-index "0x10e520 str x13, [x19, #0x68]")
                         (cur-insn insn-mem)
                         (vmp-info '(:insn-mem () :insn-index () :insn () :op ()))
                         (visited (make-hash-table :test 'equal)))
  "Mark instruction related to vmp. Add color in links attribute."
  ;; if visited is list, it will be simple, but will lose some mark (link direct between different operator)
  ;; 1. simple check (not (member cur-insn visited))
  ;; 2. simple push alreay visited insn (push cur-insn visited)
  ;; 3. recurive call mark-vmp need copy: (copy-tree visited)
  (let* ((*package* (find-package :trace-analyse)))
    (loop while (let ((cur-visited (gethash cur-insn visited)))
                  (not (and cur-visited
                            (loop for key in '(:insn-mem :insn-index :insn :op)
                                  always (subsetp (getf vmp-info key) (getf cur-visited key) :test 'equal)))))
          do (multiple-value-bind (off insn) (get-offset-and-isn cur-insn)
               (declare (ignore insn))
               (setf vmp-info (mark-vmp-ins (gethash cur-insn links)
                                            insn-mem insn-index cur-insn vmp-info
                                            (get-rizinil off)))
               (setf (gethash cur-insn visited)
                     (let ((cur-visited (gethash cur-insn visited (list :insn-mem () :insn-index () :insn () :op ()))))
                       (loop for key in '(:insn-mem :insn-index :insn :op)
                             append (list key (union (getf vmp-info key) (getf cur-visited key) :test 'equal)))))
               (let ((nexts (getf (gethash cur-insn links) :next)))
                 (when (car nexts)
                   (setf cur-insn (car nexts)))
                 (loop for next in (cdr nexts)
                       do (mark-vmp links
                                    :insn-mem insn-mem
                                    :insn-index insn-index
                                    :cur-insn next
                                    :vmp-info (copy-tree vmp-info)
                                    :visited visited)))))
    links))

;; (defun mark-vmp (links &key (insn-mem "0x10e51c ldr x8, [x19, #0x28]")
;;                          (insn-index "0x10e520 str x13, [x19, #0x68]")
;;                          (vmp-info '(:insn-mem () :insn-index () :insn () :op ())))
;;   (let ((*package* (find-package :trace-analyse)))
;;     (with-open-file (stream "resources/output-10e414-first.txt" :direction :input)
;;       ;; (with-open-file (stream trace-file :direction :input)
;;       (loop for cur-insn = (read-line stream nil nil)
;;             while cur-insn
;;             when (uiop:string-prefix-p "0x" cur-insn)
;;               do (multiple-value-bind (off insn) (get-offset-and-isn cur-insn)
;;                    (declare (ignore insn))
;;                    (setf vmp-info (mark-vmp-ins (gethash cur-insn links)
;;                                                 insn-mem insn-index cur-insn vmp-info
;;                                                 (get-rizinil off))))
;;             finally (return links)))))

(defclass cfg ()
  ((links :initarg :links
          :accessor cfg-links)
   (nodes :initarg :nodes
          :accessor cfg-nodes)))

(defmethod cl-dot:graph-object-node ((graph cfg) (object list))
  (let ((table-lines
          (mapcar (lambda (line)
                    `(:tr ()
                          (:td ((:align "left"))
                               (:font ,(getf (gethash line (cfg-links graph))
                                             :attr)
                                      ,line))))
                  object)))
    (make-instance 'cl-dot:node
                   :attributes `(:label (:html ()
                                               (:table ((:border "0"))
                                                       ,@table-lines))
                                        ;; (list :left (format nil "~{~a~%~}" object))
                                        :style :filled
                                        :fontname "monospace"
                                        :shape :rect
                                        :style (:filled :rounded)
                                        :fillcolor "#eeeefa"))))

(defmethod cl-dot:graph-object-points-to ((graph cfg) (object list))
  (mapcar (lambda (next)
            (find-if (lambda (area) (string= next (car area))) (cfg-nodes graph)))
          (getf (gethash (car (last object)) (cfg-links graph)) :next)))

(defun output-cfg (so-file trace-file &key need-mark-vmp output-file)
  (setf *rizin* (rizin:rizin-open so-file))
  (let* ((links (funcall (if need-mark-vmp #'mark-vmp #'identity)
                         (get-ins-info trace-file)))
         (group-nodes (merge-ins-block links))
         (dgraph (cl-dot:generate-graph-from-roots (make-instance 'cfg :links links :nodes group-nodes)
                                                   group-nodes
                                                   '(:rankdir "TB"
                                                     ;; :splines "ortho"
                                                     ))))
    ;; (maphash (lambda (k v)
    ;;            (when (getf v :attr)
    ;;              (format t "~a~%" k)))
    ;;          links)
    (when output-file
      (cl-dot:dot-graph dgraph output-file :format :svg))
    (rizin:quit *rizin*)

    (values links group-nodes)))

;; (defmethod capstone::capstone-instruction-class :around ((engine capstone:capstone-engine))
;;   (if (and (eql (capstone:architecture engine) :arm64)
;;            (eql (capstone:mode engine) :little_endian))
;;       'capstone::capstone-instruction/arm-a64
;;       (call-next-method)))

;; (defparameter engine
;;   (make-instance 'capstone:capstone-engine :architecture :arm64 :mode :little_endian))

;; (setf *rizin* (rizin:rizin-open "resources/libAPSE_8.0.0.so"))
;; (mark-vmp (get-ins-info))

(defun main ()
  (output-cfg "resources/libAPSE_8.0.0.so" "resources/output-10e414-first.txt" :need-mark-vmp t :output-file "test-lr.svg")

  ;; (setf *rizin* (rizin:rizin-open "/home/ring/reverse_workspace/Happy_New_Year_2025_Challenge/problem3/lib/arm64-v8a/libnativelib.so"))
  ;; (output-cfg "/home/ring/reverse_workspace/Happy_New_Year_2025_Challenge/output.txt"
  ;;             :output-file "happy-new-year-problem.svg"
  ;;             :need-mark-vmp t)
  ;; (rizin:quit *rizin*)

  ;; (format t "trace main!!~%")
  ;; (let ((binary (read-ins "resources/libAPSE_8.0.0.so"))
  ;;       (engine (make-instance 'capstone:capstone-engine
  ;;                              :arch :arm64 :mode :little-endian)))
  ;;   (capstone:option engine :cs-opt-detail t)
  ;;   (format t "version: ~a ~a~%" (capstone:version) (subseq binary #x10e424 #x10e42c))
  ;;   (format t "~s~%" (capstone:disasm engine (subseq binary #x10e424 #x10e428)))
  ;;   ;; (format t "~s~%" (capstone:disasm engine (subseq binary #x10e4a4) :address #x10e4a4 :count 1))
  ;;   (capstone:capstone-close engine))
  )
