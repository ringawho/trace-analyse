(uiop:define-package trace-analyse
  (:use #:cl)
  (:export #:main))
(in-package #:trace-analyse)

(defun get-ins-info ()
  (let ((links (make-hash-table :test 'equal))
        previous)
    ;; (with-open-file (stream "./output-310bcc.txt" :direction :input)
    (with-open-file (stream "resources/output-10e414-first.txt" :direction :input)
      (loop for line = (read-line stream nil nil)
            while line
            when (uiop:string-prefix-p "0x" line)
              do
                 (unless (gethash line links)
                   (setf (gethash line links) (list :prev nil :next nil :attr '((:color "#990073")))))
                 (when previous
                   (let ((prev-entry (gethash previous links))
                         (curr-entry (gethash line links)))
                     (setf (getf prev-entry :next)
                           (adjoin line (getf prev-entry :next) :test 'equal))
                     (setf (getf curr-entry :prev)
                           (adjoin previous (getf curr-entry :prev) :test 'equal))))
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

(defun cfg ()
  (let* ((links (get-ins-info))
         (graph-nodes (merge-ins-block links))
         (dgraph (cl-dot:generate-graph-from-roots (make-instance 'cfg :links links :nodes graph-nodes)
                                                   graph-nodes
                                                   '(:rankdir "TB"
                                                     :splines "ortho"))))
    (cl-dot:dot-graph dgraph "test-lr.svg" :format :svg)))

;; (defmethod capstone::capstone-instruction-class :around ((engine capstone:capstone-engine))
;;   (if (and (eql (capstone:architecture engine) :arm64)
;;            (eql (capstone:mode engine) :little_endian))
;;       'capstone::capstone-instruction/arm-a64
;;       (call-next-method)))

;; (defparameter engine
;;   (make-instance 'capstone:capstone-engine :architecture :arm64 :mode :little_endian))

(defun main ()
  (format t "trace main!!~%")
  (let ((binary (read-ins "resources/libAPSE_8.0.0.so"))
        (engine (make-instance 'capstone:capstone-engine
                               :arch :arm64 :mode :little-endian)))
    (capstone:option engine :cs-opt-detail t)
    (format t "version: ~a ~a~%" (capstone:version) (subseq binary #x10e424 #x10e42c))
    (format t "~s~%" (capstone:disasm engine (subseq binary #x10e424 #x10e428)))
    ;; (format t "~s~%" (capstone:disasm engine (subseq binary #x10e4a4) :address #x10e4a4 :count 1))
    (capstone:capstone-close engine)))

