ANDROID ?= yes
TARGET ?= ""

ifeq ($(ANDROID),yes)
TAG=travis-android
else
TAG=travis
endif

TAGS=travis travis-android

image: $(TAG)

all: $(TAG)
	docker run -e "ANDROID=$(ANDROID)" -e "TARGET=$(TARGET)" --rm --init --privileged -it "pwntools/pwntools:$(TAG)"

shell: image
	docker run --rm --init --privileged --entrypoint /bin/bash -it pwntools/pwntools:$(TAG)

$(TAGS): travis/$(ARCHIVE)
	make -C "$@"
	cp run.sh "$@"
	docker build -t pwntools/pwntools:$@ $@

travis-android: travis

clean:

FORCE:
.PHONY: all image $(TAGS)
