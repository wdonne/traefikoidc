FROM busybox:1.37.0
USER 1000:1000
COPY oidc.go go.mod go.sum Makefile .traefik.yml /src/github.com/wdonne/traefikoidc/
COPY vendor /src/github.com/wdonne/traefikoidc/vendor/
ENTRYPOINT ["cp", "-r", "src", "/plugins-local"]
