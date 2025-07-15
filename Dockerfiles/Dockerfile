# Build the manager binary
ARG GOLANG_VERSION=1.23

ARG BUILDPLATFORM
ARG TARGETPLATFORM

################################################################################
FROM --platform=$BUILDPLATFORM registry.access.redhat.com/ubi9/toolbox as manifests
ARG USE_LOCAL=false
ARG OVERWRITE_MANIFESTS=""
ARG FORK_ORG=""
ARG LOCAL_MODE=false
ARG LOCAL_CHECKOUTS_DIR=""
ARG BRANCH_NAME=""
USER root
WORKDIR /
COPY opt/manifests/ /opt/manifests/
COPY get_all_manifests.sh get_all_manifests.sh

# Copy local checkouts if LOCAL_MODE is enabled and they exist
# This assumes local checkouts are available in the build context
RUN if [ "${LOCAL_MODE}" = "true" ] && [ -n "${LOCAL_CHECKOUTS_DIR}" ]; then \
        echo "Local mode enabled, checking for local checkouts..."; \
        if [ -d "${LOCAL_CHECKOUTS_DIR}" ]; then \
            echo "Copying local checkouts from ${LOCAL_CHECKOUTS_DIR}"; \
            cp -r ${LOCAL_CHECKOUTS_DIR} /local-checkouts/; \
        else \
            echo "Warning: Local checkouts directory ${LOCAL_CHECKOUTS_DIR} not found, will use git clone"; \
        fi; \
    fi

# Fetch manifests using the enhanced script
RUN if [ "${USE_LOCAL}" != "true" ]; then \
        rm -rf /opt/manifests/*; \
        MANIFEST_ARGS="${OVERWRITE_MANIFESTS}"; \
        if [ -n "${FORK_ORG}" ] && [ -z "${OVERWRITE_MANIFESTS}" ]; then \
            MANIFEST_ARGS="--fork-org=${FORK_ORG}"; \
        fi; \
        if [ -n "${BRANCH_NAME}" ] && [ -z "${OVERWRITE_MANIFESTS}" ]; then \
            MANIFEST_ARGS="${MANIFEST_ARGS} --branch=${BRANCH_NAME}"; \
        fi; \
        if [ "${LOCAL_MODE}" = "true" ]; then \
            echo "LOCAL_MODE is enabled, skipping manifest fetching (assuming pre-populated)"; \
            export SKIP_MANIFESTS_FETCH=true; \
        fi; \
        if [ "${LOCAL_MODE}" = "true" ] && [ -d "/local-checkouts" ]; then \
            MANIFEST_ARGS="${MANIFEST_ARGS} --local-mode --local-checkouts-dir=/local-checkouts"; \
        fi; \
        echo "Running: ./get_all_manifests.sh ${MANIFEST_ARGS}"; \
        ./get_all_manifests.sh ${MANIFEST_ARGS}; \
    fi

# Clean up unwanted directories and files from manifests
RUN rm -rf /opt/manifests/*/e2e /opt/manifests/*/scorecard /opt/manifests/*/test /opt/manifests/*/samples /opt/manifests/*/example-* \
    && find /opt/manifests -name "README.md" -delete

# Copy monitoring config
COPY config/monitoring/ /opt/manifests/monitoring
# Copy ods-configs
COPY config/osd-configs/ /opt/manifests/osd-configs

################################################################################
FROM --platform=$BUILDPLATFORM registry.access.redhat.com/ubi9/go-toolset:$GOLANG_VERSION as builder
ARG CGO_ENABLED=1
ARG TARGETARCH
USER root
WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY api/ api/
COPY internal/ internal/
COPY cmd/main.go cmd/main.go
COPY pkg/ pkg/

# Build stripe out debug info to minimize binary size
RUN CGO_ENABLED=${CGO_ENABLED} GOOS=linux GOARCH=${TARGETARCH} go build -a -ldflags="-s -w" -tags strictfipsruntime -o manager cmd/main.go

################################################################################
FROM --platform=$TARGETPLATFORM registry.access.redhat.com/ubi9/ubi-minimal:latest
WORKDIR /
COPY --from=builder /workspace/manager .
COPY --chown=1001:0 --from=manifests /opt/manifests /opt/manifests
# Recursive change all files
RUN chown -R 1001:0 /opt/manifests &&\
    chmod -R g=u /opt/manifests
USER 1001

ENTRYPOINT ["/manager"]
