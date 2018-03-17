# By specifying each sub-make as a separate command, make -j won't try to build
# multiple ports in parallel (which can fail as they try to build the plasm cross-
# compiler simultaneously).
.PHONY: all
all:
	$(MAKE) apple
	$(MAKE) acorn

# These port targets aren't strictly necessary but they slightly reduce noise.
apple:
	$(MAKE) -f makefile.apple $@
acorn:
	$(MAKE) -f makefile.acorn $@

# Last-resort rule; matches anything.
%::
	for PORT in apple acorn; do $(MAKE) -f makefile.$$PORT $@; done
