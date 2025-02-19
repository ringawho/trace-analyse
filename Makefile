LISP ?= sbcl

exec: build
	@echo Executing ...
	@./analyse

test:
	@$(LISP) --noinform                                       \
		--eval '(push (uiop:getcwd) asdf:*central-registry*)' \
		--eval '(pushnew :libcapstone6 *features*)'           \
		--eval '(asdf:test-system :trace-analyse)'            \
		--quit

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
