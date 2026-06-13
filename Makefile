IMAGE ?= nemotron-moderation-adapter
TAG ?= latest

.PHONY: build docker-build docker-push test

build:
	go build -trimpath -ldflags="-s -w" -o bin/nemotron-moderation-adapter ./cmd/server

test:
	go test ./...

docker-build:
	docker build -t $(IMAGE):$(TAG) .

docker-push:
	docker push $(IMAGE):$(TAG)
