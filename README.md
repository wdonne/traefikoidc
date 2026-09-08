# OpenID Connect Client

This middleware orchestrates the OpenID Connect authorization code flow. It intercepts requests and starts the flow if they don't bear a valid JWT. The ID token it obtains is used as an HTTP-only cookie called `access_token` to track the user. All forwarded requests will have a bearer token.

Several IDPs can be configured. Requests can trigger the flow with the desired IDP by adding the URL query parameter `idp=<name>`. When this parameter is absent, the first segment of the domain name will be tried. If that IDP doesn't exist either, the IDP with the name `default` will be used. If there is no matching IDP, the request will result in status code 401 (Unauthorized).

You log out with the URL `https://<your-domain>/<contextPath>/logout`. If the IDP has an end-session endpoint, the user will also be logged out of the IDP.

## Configuration

|Field|Mandatory|Default value|Description|
|---|---|---|---|
|contextPath|No|Empty string|The value is a path that is the prefix of the callback, onbehalfof and logout URL paths. It is also the path used for the token cookie.|
|encryptionSecretFile|Yes|None|This is a path to a JSON file with the field `secret`, containing an AES-compatible key. The key should be either 16, 24 or 32 characters long. You can inject the JSON file with a Kubernetes secret. The secret is used to encrypt the `state` field in the authorization code flow. It is interpreted as plain bytes, so a US-ASCII string would work.|
|idps|Yes|None|The array of IDP configurations.|
|idps.audiences|No|None|An array of audience identifiers that are used to verify tokens. It is highly recommended to set this to avoid privilege elevation issues when the provider is also used for other applications.|
|idps.clientSecretFile|Yes|None|The value is a path to a JSON file with the fields `clientID` and `clientSecret`. You can inject the JSON file with a Kubernetes secret.|
|idps.name|Yes|None|The name of the IDP. If the value is `default`, then this IDP will be used when none is provided through the URL query parameter `idp`.|
|idps.postLogoutUrl|Yes|None|This is the URL to which the user is redirected after logging out. If your IDP requires the URL to be pre-configured, it should match this field.|
|idps.providerUrl|Yes|None|The OpenID Connect discovery URL.|
|idps.scopes|No|The discovered values except `offline_access`|An array of scope names.|
|internalIssuer|No|None|An issuer with which an ID token can be exchanged for an internal token. This token will then be used instead to track the user. The endpoint will receive the current ID token as a bearer token. If the internal issuer returns the status code 404, the current ID token is kept. This way you can have guest users who don't have any internal rights.|
|internalIssuer.audiences|No|None|The array of audiences that is used to verify the tokens it issues. It is highly recommended to set this when using an internal issuer.|
|internalIssuer.onBehalfOf|No|None|If the internal issuer supports administrators to switch to another user, then this configuration can be used to set it up. The internal token of the administrator will be exchanged for the token of another user. This is useful for support situations where the credentials of the other user don't have to be provided.|
|internalIssuer.onBehalfOf.callbackPath|Yes|None|The application where the user is selected will receive the URL parameter `url` with this path. After the selection it should redirect back to it, with the URL parameter `user` appended. The value of this parameter should be the `sub` claim. The `user` parameter will be forwarded to the internal issuer to obtain a token that represents the user.|
|internalIssuer.onBehalfOf.eligibleClaim|Yes|None|This is the name of the Boolean claim in the internal token. If it is set to `true`, the user is allowed to proceed with the on-behalf-of exchange.|
|internalIssuer.onBehalfOf.issuerPath|Yes|None|The path for the internal issuer endpoint where a token for another user can be obtained.|
|internalIssuer.onBehalfOf.redirectPath|Yes|None|The path in the URL space where the user selection application is. The redirect will carry the `url` URL parameter.|
|internalIssuer.url|Yes|None|The endpoint for the internal issuer. It will also be used to verify the tokens it issues. This means the `iss` claim should be set to this URL.|
|lazyDiscovery|No|`false`|When set, it postpones the IDP discovery phase until the first request arrives.|
|notBearerToken|No|`false`|Adds the "Bearer " prefix to the token header value.|
|tokenHeader|No|Authorization|Sets the name of the HTTP header on the request that is forwarded. You can use this, for example, to emulate JWT Proxy by setting the name to `X-JWT-Assertion` and the configuration field `notBearerToken` to `true`.|
|whoami|No|false|When this is turned on, a cookie with the name `whoami` will be set. It is a JSON object with the claims for the user. This can be used to enhance the UX.|

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
      contextPath: /api
      encryptionSecretFile: /oidc/encryption/encryption_secret.json
      idps:
        - name: google
          providerUrl: "https://accounts.google.com"
          audiences:
            - cc2ec774-504e-40bc-8779-11382b98c651
          postLogoutUrl: "https://my.domain/api?idp=google"
          clientSecretFile: /oidc/google/client.json
          scopes:
            - openid
            - email
        - name: default
          providerUrl: "https://login.microsoftonline.com/{tenant ID}/v2.0"
          audiences:
            - 7da8ff90-c786-4e75-8ea8-b6416d29782c
          postLogoutUrl: "https://my.domain/api"
          clientSecretFile: /oidc/microsoft/client.json
      internalIssuer:
        url: https://my-issuer
        audiences:
          - b278aab5-31a1-4aa1-b05f-020e82edbf84
        onBehalfOf:
          callbackPath: /onbehalfof
          eligibleClaim: superadmin
          issuerPath: /onbehalfof
          redirectPath: /select-user
```

## Deployment

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

If you don't want to load the plugin through `github.com/wdonne/traefikoidc`, you can also use
the image `wdonne/traefikoidc:<version>` with an init container and an `emptyDir` volume. The
container will copy the plugin to `/plugins-local`. You should add something like the following to
the Traefik values file:

```yaml
volumes:
  - name: traefikoidc
    emptyDir: { }
    mountPath: /plugins-local
deployment:
  initContainers:
    - name: traefikoidc
      image: wdonne/traefikoidc:<version>
      volumeMounts:
        - name: traefikoidc
          mountPath: /plugins-local
additionalArguments:
  - "--experimental.localPlugins.traefikoidc.modulename=github.com/wdonne/traefikoidc"
```

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/wdonne/traefikoidc)
