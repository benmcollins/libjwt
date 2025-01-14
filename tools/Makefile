PANDOC ?= pandoc

MANSECTION ?= 1

MANPAGE.md = $(PANDOC) --standalone $(PANDOCFLAGS) --to man

MAN_PAGES = jwt-verify.1 jwt-generate.1 key2jwk.1 jwk2key.1

all: $(MAN_PAGES)

%.$(MANSECTION): %.$(MANSECTION).md
	$(MANPAGE.md) $< -o $@

clean:
	rm -f $(MAN_PAGES)
