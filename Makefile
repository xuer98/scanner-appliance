# Scanner appliance — Phase 1 build targets.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo dev)
CP_URL  ?= https://appliance.tprm.example.com
LDFLAGS  = -s -w -X main.version=$(VERSION) -X main.defaultCPURL=$(CP_URL)
GOFLAGS  = -trimpath

.PHONY: all build build-linux test vet lint dev-ca dev-cp dev-appliance clean ova docker

all: vet test build

build:            ## native binaries into bin/
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/applianced ./daemon/cmd/applianced
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/cp-api     ./controlplane/cmd/cp-api

build-linux:      ## static linux/amd64 + arm64 (what the image and container use)
	./ci/build.sh --dev --version $(VERSION)

test:
	go test ./...

vet:
	go vet ./...
	gofmt -l . | tee /dev/stderr | test -z "$$(cat)"

lint:
	shellcheck -x ci/*.sh ci/smoke/*.sh packer/scripts/*.sh packer/*.sh docker/*.sh

dev-ca:           ## dev PKI under dev/pki (root, intermediate, keys)
	@test -f dev/pki/root.pem || go run ./controlplane/cmd/cp-api ca init --dir dev/pki --org "TPRM Dev"

dev-cp: dev-ca    ## run cp-api in-memory on :8443 (enroll) / :9443 (mTLS + admin), admin token "dev"
	go run ./controlplane/cmd/cp-api serve --dev --pki-dir dev/pki --object-dir dev/objects --public-url https://localhost:9443

dev-appliance: dev-ca  ## run the daemon locally against dev-cp; set CODE=... from `cp-api admin create-appliance`
	APPLIANCE_ROOT_CA=dev/pki/root.pem APPLIANCE_STATE_DIR=dev/state APPLIANCE_RUN_DIR=dev/run \
	APPLIANCE_CP_URL=https://localhost:8443 APPLIANCE_CODE=$(CODE) \
	go run ./daemon/cmd/applianced run --log-level debug

dev-tty: dev-ca   ## the console against the local daemon state
	APPLIANCE_ROOT_CA=dev/pki/root.pem APPLIANCE_STATE_DIR=dev/state APPLIANCE_RUN_DIR=dev/run \
	go run ./daemon/cmd/applianced tty

ova: build-linux  ## qcow2 via packer, then OVA + VHDX (needs packer, qemu, kvm)
	cd packer && packer init base.pkr.hcl && packer build -var version=$(VERSION) base.pkr.hcl
	./packer/build-ova.sh packer/output-appliance/appliance-$(VERSION).qcow2 $(VERSION)
	./packer/build-vhdx.sh packer/output-appliance/appliance-$(VERSION).qcow2 $(VERSION)

docker: dev-ca    ## container images (appliance + cp-api)
	docker build -f docker/Dockerfile --build-arg VERSION=$(VERSION) -t scanner-appliance:$(VERSION) .
	docker build -f docker/Dockerfile.cp-api --build-arg VERSION=$(VERSION) -t cp-api:$(VERSION) .

clean:
	rm -rf bin dist dev/state dev/run dev/objects
