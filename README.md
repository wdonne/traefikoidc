# OpenID Connect Client

This middleware orchestrates the OpenID Connect authorization code flow. It intercepts requests and starts the flow if they don't bear a valid JWT. The ID token it obtains is used as an HTTP-only cookie called `access_token` to track the user. All forwarded requests will have a bearer token.

Several IDPs can be configured. Requests can trigger the flow with the desired IDP by adding the URL query parameter `idp=<name>`. When this parameter is absent, the IDP with the name `default` will be used. If there is no matching IDP, the request will result in status code 401 (Unauthorized).

The plugin has two configuration parameters. The parameter `encryptionSecretFile` should contain the path to a JSON file with the field `secret`. Its value should be an AES-compatible key, which means it should be either 16, 24 or 32 characters long. You can inject the JSON file with a Kubernetes secret. The secret is used to encrypt the `state` field in the authorization code flow.

The second configuration parameter is `idps`, which is an array. Each entry has the mandatory fields `name`, `providerUrl` and `clientSecretFile`, and the optional fields `scopes` and `postLogoutUrl`. The latter should contain the path to a JSON file with the fields `clientID` and `clientSecret`. You can inject it with a Kubernetes secret.

The scopes that are requested are the ones that are discovered through the provider URL, except `offline_access`. You can override the requested scopes with the field `scopes`.

This is an example of a middleware configuration:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: my-oidc
  namespace: traefik
spec:
  plugin:
    traefikoidc:
      encryptionSecretFile: /oidc/encryption/encryption_secret.json
      idps:
        - name: google
          providerUrl: "https://accounts.google.com"
          postLogoutUrl: "https://my.domain/api?idp=google"
          clientSecretFile: /oidc/google/client.json
          scopes:
            - openid
            - email
        - name: default
          providerUrl: "https://login.microsoftonline.com/{tenant ID}/v2.0"
          postLogoutUrl: "https://my.domain/api"
          clientSecretFile: /oidc/microsoft/client.json
```

In the Traefik values file you would add a volumes section like this:

```yaml
volumes:
  - name: oidc-client-google
    type: secret
    mountPath: /oidc/google
  - name: oidc-client-microsoft
    type: secret
    mountPath: /oidc/microsoft
  - name: oidc-encryption-secret
    type: secret
    mountPath: /oidc/encryption
```

If you don't want to load the plugin through `github.com/wdonne/traefikoidc`, you can also use the image `wdonne/traefik-oidc:<version>` with an init container and an `emptyDir` volume. The container will copy the plugin to `/plugins-local`. You should add something like the following to the Traefik values file:

```yaml
volumes:
  - name: traefikoidc
    emptyDir: { }
    mountPath: /plugins-local
deployment:
  initContainers:
    - name: traefikoidc
      image: wdonne/traefik-oidc:1.0
      volumeMounts:
        - name: traefikoidc
          mountPath: /plugins-local
additionalArguments:
  - "--experimental.localPlugins.traefikoidc.modulename=github.com/wdonne/traefikoidc"
```
