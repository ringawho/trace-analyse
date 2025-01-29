LISP ?= sbcl

exec: build
	@./analyse

build:
	@$(LISP) --noinform                                       \
		--eval '(push (uiop:getcwd) asdf:*central-registry*)' \
		--eval '(pushnew :libcapstone6 *features*)'           \
		--eval '(asdf:load-system :trace-analyse)'            \
		--eval '(asdf:make :trace-analyse)'                   \
		--quit

build-force:
	@$(LISP) --noinform                                       \
		--eval '(push (uiop:getcwd) asdf:*central-registry*)' \
		--eval '(pushnew :libcapstone6 *features*)'           \
		--eval '(asdf:load-system :trace-analyse :force t)'   \
		--eval '(asdf:make :trace-analyse)'                   \
		--quit
