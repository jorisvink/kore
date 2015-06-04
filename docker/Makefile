TAG=$(shell git describe --abbrev=0 --tags `git rev-list --tags --max-count=1`)

all: build run

build:
	docker build -t kore-build -f build/Dockerfile build/
build-tag:
	docker tag -f kore-build kore/build

run:
	docker build -t kore-run -f run/Dockerfile run/
run-tag:
	docker tag -f kore-run kore/run:$(TAG)

release: build build-tag run run-tag

clean:
	docker rmi -f kore-build kore-run

.PHONY: all build build-tag run run-tag release clean
