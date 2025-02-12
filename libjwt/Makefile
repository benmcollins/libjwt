FILES = jwt-builder.c jwt-checker.c

all: $(FILES)

jwt-%.c: %.sed jwt-common.c
	sed -f $< jwt-common.c > $@
