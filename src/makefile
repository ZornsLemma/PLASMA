.PHONY: all
all: apple acorn

# These port targets aren't strictly necessary but they slightly reduce noise.
apple:
	$(MAKE) -f makefile.apple $@
acorn:
	$(MAKE) -f makefile.acorn $@

# Last-resort rule; matches anything.
%::
	for PORT in apple acorn; do $(MAKE) -f makefile.$$PORT $@; done
