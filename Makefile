#
# Author: Ross McDonald (ross.mcdonald@gitwarden.com)
# Copyright 2017, Summonry Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# For usage information, simply run `make` from the root directory of
# the gitwarden-agent repository.
#
# For bugs or feature requests, please file an issue against the GitWarden Agent
# repository on Github at:
#
# https://github.com/gitwarden/gitwarden-agent
#

GIT_BRANCH = $(shell git rev-parse --abbrev-ref HEAD)
GIT_TAG = $(shell git describe --always --tags --abbrev=0 | tr -d 'v')
GIT_COMMIT = $(shell git rev-parse HEAD)

all: envcheck gitwarden-agent ## Build everything

gitwarden-agent: ## Generate a build of the gitwarden-agent
	$(eval LINKER_FLAGS = -X main.version=$(GIT_TAG) -X main.branch=$(GIT_BRANCH) -X main.commit=$(GIT_COMMIT))
ifeq ($(static), true)
	$(eval COMPILE_PREPEND = CGO_ENABLED=0 )
	$(eval COMPILE_PARAMS = -ldflags "-s $(LINKER_FLAGS)" -a -installsuffix cgo )
else
	$(eval COMPILE_PARAMS = -ldflags "$(LINKER_FLAGS)" )
endif
	@echo "Building '$@'"
	$(COMPILE_PREPEND)go build $(COMPILE_PARAMS)./cmd/$@

release: ## Tag and generate a release build (example: make release version=1.2.3)
	git tag $(version)
	git push origin --tags
	make docker-package

envcheck: ## Check environment for any common issues
ifneq ($(shell which go &>/dev/null; echo $$?),0)
	$(error "Go not installed.")
endif

docker-build: clean ## Create a build in Docker
	./scripts/docker-image.sh
	./scripts/docker-build.sh

docker-package: docker-build ## Generate packages in Docker
	./scripts/docker-package.sh

docker-image: ## Generate a Docker image for Docker Hub - RUN AFTER UPDATING REPO
	docker build --no-cache -t gitwarden/gitwarden-agent:v$(GIT_TAG) -f Dockerfile .
	docker tag gitwarden/gitwarden-agent:v$(GIT_TAG) gitwarden/gitwarden-agent:latest
	docker push gitwarden/gitwarden-agent:v$(GIT_TAG)
	docker push gitwarden/gitwarden-agent:latest

package: ## Generate packages
	./scripts/package.sh

get: ## Retrieve Go dependencies
	PATH=$$PATH:$$GOPATH/bin dep ensure

get-update: ## Retrieve updated Go dependencies
	PATH=$$PATH:$$GOPATH/bin dep ensure -update

clean: ## Remove existing binaries
	@for target in gitwarden-agent; do \
		rm -f $$target ; \
	done

help: ## Display usage information
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[32m%-31s\033[0m %s\n", $$1, $$2}'

.PHONY: help,envcheck,docker-build,docker-package,docker-image,package,get,get-update
.DEFAULT_GOAL := help
