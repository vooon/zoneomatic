.PHONY: k3d k3d-cluster k3d-build k3d-deploy k3d-test k3d-clean k3d-redeploy

# --- k3d cert-manager test ---
#
# Issues certificates with cert-manager's rfc2136 solver against zoneomatic in
# a throwaway k3d cluster. The cluster gets its own kubeconfig file, so the
# targets never touch the default kubectl context.

K3D_CLUSTER          ?= zoneomatic-e2e
K3D_KUBECONFIG       ?= $(CURDIR)/.k3d-kubeconfig
K3D_NAMESPACE        := zoneomatic-e2e
E2E_IMAGE            := zoneomatic:e2e
CERT_MANAGER_VERSION ?= v1.21.2

KUBECTL := kubectl --kubeconfig $(K3D_KUBECONFIG)
HELM    := helm --kubeconfig $(K3D_KUBECONFIG)

k3d-cluster:
	k3d cluster create $(K3D_CLUSTER) --no-lb \
		--k3s-arg '--disable=traefik@server:0' \
		--kubeconfig-update-default=false --kubeconfig-switch-context=false \
		--wait --timeout 3m
	k3d kubeconfig get $(K3D_CLUSTER) > $(K3D_KUBECONFIG)
	chmod 600 $(K3D_KUBECONFIG)

k3d-build:
	docker build -f Dockerfile.e2e -t $(E2E_IMAGE) .
	k3d image import $(E2E_IMAGE) -c $(K3D_CLUSTER)

k3d-deploy:
	$(KUBECTL) apply -f tests/k3d/manifests/namespace.yaml
	$(KUBECTL) apply -f tests/k3d/manifests/zoneomatic.yaml -f tests/k3d/manifests/pebble.yaml
	$(HELM) upgrade --install cert-manager cert-manager \
		--repo https://charts.jetstack.io --version $(CERT_MANAGER_VERSION) \
		--namespace cert-manager --create-namespace \
		--values tests/k3d/cert-manager-values.yaml \
		--wait --timeout 5m
	$(KUBECTL) apply -f tests/k3d/manifests/issuer.yaml
	$(KUBECTL) -n $(K3D_NAMESPACE) rollout status deployment/zoneomatic --timeout=3m
	$(KUBECTL) -n $(K3D_NAMESPACE) rollout status deployment/pebble --timeout=3m

k3d-test:
	KUBECONFIG=$(K3D_KUBECONFIG) go test -tags=k3d -v -timeout=10m -count=1 ./tests/k3d/...

k3d-clean:
	k3d cluster delete $(K3D_CLUSTER)
	rm -f $(K3D_KUBECONFIG)

k3d: k3d-cluster k3d-build k3d-deploy k3d-test

# Rebuild and restart zoneomatic in an existing cluster (resets the zone file).
k3d-redeploy: k3d-build
	$(KUBECTL) apply -f tests/k3d/manifests/zoneomatic.yaml
	$(KUBECTL) -n $(K3D_NAMESPACE) rollout restart deployment/zoneomatic
	$(KUBECTL) -n $(K3D_NAMESPACE) rollout status deployment/zoneomatic --timeout=3m
