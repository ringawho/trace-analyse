(in-package #:capstone)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun get-cstruct-real-data (field fields struct-name value-param-sym value-sym)
    (destructuring-bind (field-name type &key (count 0 count-p) &allow-other-keys) field
      (declare (ignore count))
      (cond
        ((and (eql type :char) count-p)
         `(setf (getf ,value-sym ',field-name)
                (cffi:foreign-string-to-lisp (getf ,value-sym ',field-name))))
        (count-p
         (let ((arr-var (gensym))
               (loop-var (gensym))
               (count-var (gensym))
               (count-sym-name (alexandria:symbolicate field-name '-count)))
           (when (find-if (lambda (f) (eql (car f) count-sym-name)) fields)
             `(let* ((,count-var (getf ,value-sym ',count-sym-name))
                     (,arr-var (make-array ,count-var)))
                (dotimes (,loop-var ,count-var)
                  ;; ,(when (listp type)
                  ;;    `(handler-case
                  ;;         (format t "~s~%" (cffi:mem-aref
                  ;;                           (cffi:inc-pointer ,value-param-sym
                  ;;                                             (cffi:foreign-slot-offset
                  ;;                                              '(:struct ,struct-name)
                  ;;                                              ',field-name))
                  ;;                           ',type
                  ;;                           ,loop-var))
                  ;;       (error (e)
                  ;;         (format t "Caught and ignored error when list: ~a~%" e))))
                  (setf (aref ,arr-var ,loop-var)
                        ,(if (listp type)
                             ;; because list it need ',type
                             ;; keyword is dont need, so is ,type
                             `(cffi:mem-aref (cffi:inc-pointer ,value-param-sym
                                                               (cffi:foreign-slot-offset
                                                                '(:struct ,struct-name)
                                                                ',field-name))
                                             ',type
                                             ,loop-var)
                             `(cffi:mem-aref (getf ,value-sym ',field-name) ,type ,loop-var))))
                (setf (getf ,value-sym ',field-name) ,arr-var)))))
        ((listp type)
         (trivia:match type
           ((list :pointer (list :struct inner-type))
            `(setf (getf ,value-sym ',field-name)
                   (cffi:mem-ref (getf ,value-sym ',field-name) '(:struct ,inner-type)))
            )))
        )))
  (defun defcstruct-hook (name-and-options &rest fields)
    (destructuring-bind (name)
        (uiop:ensure-list name-and-options)
      (let ((value-param-sym (gensym))
            (type-param-sym (gensym))
            (value-sym (gensym)))
        ;; it should be list of expression, the return value will be expanded using ,@
        `((defmethod cffi:translate-from-foreign (,value-param-sym (,type-param-sym ,(alexandria:symbolicate name '-tclass)))
            (let ((,value-sym (call-next-method)))
              ;; (format t "translate-from-foreign ~a~%~s~%" ,type-param-sym ,value-sym)
              ,@(remove-if-not
                 'identity
                 (mapcar (lambda (field)
                           (get-cstruct-real-data field fields
                                                  name value-param-sym value-sym))
                         fields))
              ,value-sym))))))
  (setf cffi::*defcstruct-hook* #'defcstruct-hook))

(defmethod cffi:translate-from-foreign (p (type cffi::foreign-union-type))
  ;; Iterate over slots, make plist
  (if (cffi::bare-struct-type-p type)
      p
      (let ((plist (list)))
        (loop for slot being the hash-value of (cffi::structure-slots type)
              for name = (cffi::slot-name slot)
              do (setf (getf plist name)
                       ;; (handler-case
                       ;;     (cffi::foreign-struct-slot-value p slot)
                       ;;   (error (e)
                       ;;     (format t "Caught and ignored error: ~a~%" e)))
                       (ignore-errors
                        (cffi::foreign-struct-slot-value p slot))))
        plist)))

