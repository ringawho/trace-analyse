;; (eval-when (:load-toplevel :execute)
;;   (operate 'load-op 'cffi-grovel))

(defsystem "trace-analyse"
  :version "0.0.1"
  :author "ring"
  :license ""
  :description ""
  :build-operation "program-op"
  :build-pathname "analyse"
  :entry-point "trace-analyse:main"

  :depends-on (:uiop :cl-dot :cl-ppcre :trivia :com.inuoe.jzon :alexandria
               :clingon :trace-analyse/capstone :trace-analyse/rizin)
  :components ((:module "src"
                :components
                ((:file "main"))))
  :in-order-to ((test-op (test-op "trace-analyse/tests"))))

(defsystem "trace-analyse/tests"
  :author ""
  :license ""
  :depends-on (:trace-analyse :rove :marshal :alexandria)
  :components ((:module "tests"
                :components
                ((:file "main"))))
  :description "Test system for trace-analyse"
  :perform (test-op (op c) (symbol-call :rove :run c)))

(defsystem "trace-analyse/capstone"
  :version "0.0.1"
  :author "ring"
  :license ""
  :depends-on (:uiop :cffi :alexandria :trivia)
  ;; :defsystem-depends-on ("cffi-grovel")
  :components ((:module "capstone"
                :components
                ((:file "package")
                 (:file "ffi-utils")
                 ;; (:cffi-grovel-file "grovel")
                 (:file "arm64-ffi")
                 (:file "ffi")
                 (:file "capstone"))))
  :description "")

(defsystem "trace-analyse/rizin"
  :version "0.0.1"
  :author "ring"
  :license ""
  :depends-on (:uiop :cl-ppcre)
  :components ((:module "rizin"
                :components
                ((:file "rizin"))))
  :description "")
