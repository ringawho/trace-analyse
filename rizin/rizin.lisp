(uiop:define-package rizin
  (:use #:cl)
  (:export #:rizin-open
           #:cmd
           #:il
           #:quit))

(in-package #:rizin)

(define-condition rizin-command-error (error)
  ((msg :initarg :msg :accessor msg))
  (:report (lambda (condition stream)
             (format stream "[rizin] ~a~%" (msg condition)))))

(defclass rizin ()
  ((process :initarg :process :accessor process)
   (input :initarg :input :accessor input)
   (output :initarg :output :accessor output)
   (err-output :initarg :err-output :accessor err-output)))

(defun rizin-open (file-name)
  (let* ((process (uiop:launch-program (list "rizin" "-q0" file-name)
                                       :input :stream :output :stream
                                       :error-output :stream))
         (input (uiop:process-info-input process))
         (output (uiop:process-info-output process))
         (err-output (uiop:process-info-error-output process)))
    (uiop:read-null-terminated-string output)
    (when (listen err-output)
      (read-line err-output))
    (make-instance 'rizin
                   :process process
                   :input input
                   :output output
                   :err-output err-output)))

(defgeneric cmd (r cmd-str &key offset)
  (:method ((r rizin) (cmd-str string) &key (offset 0 offset-p))
    (when offset-p
      (cmd r (format nil "s ~a" offset)))
    (with-slots (input output err-output) r
      (write-line cmd-str input)
      (force-output input)
      (when (listen err-output)
        (error (make-condition 'rizin-command-error
                               :msg (read-line err-output))))
      (string-trim '(#\Space #\Tab #\Newline)
                   (uiop:read-null-terminated-string output)))))

(defgeneric il (r &key size offset)
  (:method ((r rizin) &key (size 1) (offset 0 offset-p))
    (let ((cmd-str (format nil "aoi ~a" size)))
      (if offset-p
          (cmd r cmd-str :offset offset)
          (cmd r cmd-str)))))

(defgeneric quit (r)
  (:method ((r rizin))
    (cmd r "q")
    (with-slots (process) r
      (uiop:close-streams process))))

