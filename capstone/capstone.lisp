(in-package #:capstone)

(cffi:define-foreign-library libcapstone
  (t (:default "libcapstone")))
(cffi:use-foreign-library libcapstone)

(defun version ()
  (cffi:with-foreign-objects ((major :int)
                              (minor :int))
    (cs-version major minor)
    (values (cffi:mem-ref major :int) (cffi:mem-ref minor :int))))

(defmacro to-array ((index count) &body body)
  (let ((arr-var (gensym)))
    `(let ((,arr-var (make-array ,count)))
       (dotimes (,index ,count ,arr-var)
         (setf (aref ,arr-var ,index)
               (progn ,@body))))))

(defmacro check-error ((err handle) &body (ok-form &optional err-form))
  `(let ((,err (cs-errno (cffi:mem-ref ,handle 'cs-handle))))
     (case errno
       (:ok ,ok-form)
       (t ,err-form))))

(define-condition capstone (error)
  ((code :initarg :code :initform nil :reader code)
   (strerr :initarg :strerr :initform nil :reader strerr))
  (:report (lambda (condition stream)
             (format stream "Capstone error ~S." (strerr condition))))
  (:documentation "Capstone error."))

(define-condition disassembly (capstone)
  ((bytes :initarg :bytes :initform nil :reader disassembly-bytes))
  (:report (lambda (condition stream)
             (format stream "Disassembly error ~S on ~S."
                     (strerr condition) (disassembly-bytes condition))))
  (:documentation "Capstone disassembly error."))

(defclass capstone-engine ()
  ((arch :initarg :arch :reader arch :type keyword)
   (mode :initarg :mode :reader mode :type (or keyword list))
   (handle)))

(defmethod initialize-instance :after ((engine capstone-engine) &key)
  (with-slots (arch mode handle) engine
    (setf handle (cffi:foreign-alloc 'cs-handle))
    (let* ((actual-mode (if (listp mode)
                            (reduce #'logior mode
                                    :key (lambda (mode) (cffi:foreign-enum-value 'cs-mode mode))
                                    :initial-value 0)
                            mode))
           (errno (cs-open arch actual-mode handle)))
      (unless (eql :ok errno)
        (error (make-condition 'capstone
                               :code errno
                               :strerr (cs-strerror errno)))))))

(defgeneric capstone-close (engine)
  (:method ((engine capstone-engine))
    (with-slots (handle) engine
      (cs-close handle)
      (cffi:foreign-free handle))))

(defgeneric option (engine type value)
  (:method ((engine capstone-engine) type value)
    (with-slots (handle) engine
      (cs-option (cffi:mem-ref handle 'cs-handle)
                 type
                 (ctypecase value
                   (boolean (if value 1 0))
                   (integer value))))))

(defgeneric regs-access (engine insn*)
  (:method ((engine capstone-engine) insn*)
    (with-slots (handle) engine
      (cffi:with-foreign-objects ((regs-read :uint16 64)
                                  (regs-read-count :uint8)
                                  (regs-write :uint16 64)
                                  (regs-write-count :uint8))
        (cs-regs-access (cffi:mem-ref handle 'cs-handle)
                        insn*
                        regs-read regs-read-count
                        regs-write regs-write-count)
        (check-error (errno handle)
          nil
          (error (make-condition 'capstone
                                 :code errno
                                 :strerr (cs-strerror errno))))
        (values
         (to-array (i (cffi:mem-ref regs-read-count :uint8))
           (cffi:mem-aref regs-read :uint16 i))
         (to-array (i (cffi:mem-ref regs-write-count :uint8))
           (cffi:mem-aref regs-write :uint16 i)))))))

(defgeneric disasm (engine bytes &key address count)
  (:method ((engine capstone-engine) (bytes vector)
            &key (address 0) (count 0))
    (check-type address integer)
    (check-type count integer)
    (with-slots (handle) engine
      (cffi:with-pointer-to-vector-data (code bytes)
        (cffi:with-foreign-object (insn** '(:pointer (:pointer (:struct cs-insn))))
          (let ((ins-count (cs-disasm (cffi:mem-ref handle 'cs-handle)
                                      code
                                      (length bytes)
                                      address count insn**)))
            (when (zerop ins-count)
              (check-error (errno handle)
                (warn "Empty disassembly of ~S at ~x." code address)
                (error (make-condition 'disassembly
                                       :code errno
                                       :strerr (cs-strerror errno)
                                       :bytes code))))
            (let ((first-insn* (cffi:mem-ref insn** :pointer))
                  (insn-size (cffi:foreign-type-size '(:struct cs-insn))))
              (prog1
                  (to-array (i ins-count)
                    (let* ((insn* (cffi:inc-pointer first-insn* (* i insn-size)))
                           (lisp-insn (cffi:mem-ref insn* '(:struct cs-insn))))
                      (multiple-value-bind (regs-read regs-write) (regs-access engine insn*)
                        (setf (getf lisp-insn :regs-read) regs-read)
                        (setf (getf lisp-insn :regs-write) regs-write)
                        lisp-insn)))
                (cs-free first-insn* ins-count)))))))))

;; (let ((engine (make-instance 'capstone-engine :arch :arm64 :mode :little-endian)))
;;   (format t "cs-open success, version is ~a ~%" (version))
;;   (capstone-close engine))
;; (format t "cs open result: ~a~%" (cs-open :arm64 :little-endian ))

