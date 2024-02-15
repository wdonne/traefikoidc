FROM busybox
COPY oidc.go go.mod go.sum Makefile .traefik.yml /src/github.com/wdonne/traefikoidc/
COPY vendor /src/github.com/wdonne/traefikoidc/vendor/
ENTRYPOINT cp -r src /plugins-local
