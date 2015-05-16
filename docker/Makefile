all: build app

build:
	docker build -t kore-build -f build/Dockerfile build/
	docker tag kore-build kore/build

app:
	docker build -t kore-app -f app/Dockerfile app/
	docker tag kore-app kore/app

clean:
	docker rmi -f kore-build kore-app

.PHONY: all build app clean
