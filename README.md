# semgrep-network-broker

**NOTE:** These docs are in-progress. Feel free to direct any questions / feedback / improvements to your private channel on the Semgrep slack!

The Semgrep Network Broker facilitates secure access between Semgrep and a private network.

The broker accomplishes this by establishing a Wireguard VPN tunnel with the Semgrep backend, and then proxying inbound (Semgrep --> customer) HTTP requests through this tunnel. This approach allows Semgrep to interact with on-prem resources without having to expose them to the public internet.

Examples of inbound traffic include:

- Pull Request comments
- JIRA integrations
- Webhooks

## Setup

### Build

NOTE: The Semgrep Network broker uses [Buf](https://buf.build/) for protobuf compilation. If you are building the broker from scratch outside of Docker, make sure you have the Buf CLI installed: https://buf.build/docs/installation

- Run `make build` to build the `semgrep-network-broker` binary locally
- Run `make docker` to build a docker image
- Docker images are also published to [ghcr.io/semgrep/semgrep-network-broker](https://github.com/semgrep/semgrep-network-broker/pkgs/container/semgrep-network-broker)

### Keypairs

The broker requires a Wireguard keypair in order to establish a secure connection.

- `semgrep-network-broker genkey` generates a random private key in base64 and prints it to stdout
- `semgrep-network-broker pubkey` reads a base64 private key from stdin and prints the corresponding base64 public key to stdout

#### Example

```bash
> semgrep-network-broker genkey
some_private_key

> echo "some_private_key" | semgrep-network-broker pubkey
some_public_key
```

Your public key is safe to share. _Do not_ share your private key with anyone (including Semgrep).

### Configuration

Semgrep will help you create a configuration file tailored to your Semgrep deployment.

**Do not** alter the `wireguard` and `heartbeat` sections.

**Do not** share the value of `inbound.wireguard.privateKey`. This is your organization's private key. Reach out to Semgrep on Slack if you need to rotate your Wireguard keys.

Example:

```yaml
inbound:
  wireguard:
    localAddress: ...
    privateKey: ...
    peers:
      - publicKey: ...
        endpoint: ...
        allowedIps: ...
  heartbeat:
    url: ...
  allowlist: [...]
```

### HttpClient

The `httpClient` configuration section modifies the HTTP client used for proxying requests.

Example:

```yaml
inbound:
  httpClient:
    additionalCACerts:
      - /path/to/custom/cert.pem
```

### GitHub

The `github` configuration section simplifies granting Semgrep access to leave PR comments.

Example:

```yaml
inbound:
  github:
    baseUrl: https://github.example.com/api/v3
    token: ...
    allowCodeAccess: false # default is false, set to true to allow Semgrep to read file contents
```

Under the hood, this config adds these allowlist items:

- GET `https://github.example.com/api/v3/repos/:owner/:repo`
- GET `https://github.example.com/api/v3/repos/:owner/:repo/pulls`
- GET `https://github.example.com/api/v3/orgs/:org/installation`
- GET `https://github.example.com/api/v3/orgs/:org/repos`
- GET `https://github.example.com/api/v3/installation/repositories`
- GET `https://github.example.com/api/v3/users/:user/installation`
- GET `https://github.example.com/api/v3/users/:user/installation/repositories`
- GET `https://github.example.com/api/v3/app`
- GET `https://github.example.com/api/v3/repos/:org/:repo/actions/secrets/public-key`
- GET `https://github.example.com/api/v3/repos/:org/:repo/contents/.github/workflows/semgrep.yml`
- PUT `https://github.example.com/api/v3/repos/:org/:repo/contents/.github/workflows/semgrep.yml`
- PUT `https://github.example.com/api/v3/repos/:org/:repo/actions/secrets/SEMGREP_APP_TOKEN`
- POST `https://github.example.com/api/v3/app/installations/:id/access_tokens`
- POST `https://github.example.com/api/v3/app-manifests/:code/conversions`
- POST `https://github.example.com/api/v3/repos/:owner/:repo/pulls/:number/comments`
- POST `https://github.example.com/api/v3/repos/:owner/:repo/issues/:number/comments`

And if `allowCodeAccess` is set, additionally:

- GET `https://github.example.com/api/v3/repos/:org/:repo/contents/*`
- GET `https://github.example.com/api/v3/repos/:org/:repo/commits`

### GitLab

Similarly, the `gitlab` configuration section grants Semgrep access to leave MR comments.

Example:

```yaml
inbound:
  gitlab:
    baseUrl: https://gitlab.example.com/api/v4
    token: ...
    allowCodeAccess: false # default is false, set to true to allow Semgrep to read file contents
```

Under the hood, this config adds these allowlist items:

- DELETE `https://gitlab.example.com/api/v4/groups/:namespace/hooks/:hook`
- DELETE `https://gitlab.example.com/api/v4/projects/:project/hooks/:hook`
- GET `https://gitlab.example.com/api/v4/groups/:namespace/hooks`
- GET `https://gitlab.example.com/api/v4/namespaces/:namespace`
- GET `https://gitlab.example.com/api/v4/projects/:project`
- GET `https://gitlab.example.com/api/v4/projects/:project/members/all/:user`
- GET `https://gitlab.example.com/api/v4/groups/:namespace/members/all/:user`
- GET `https://gitlab.example.com/api/v4/projects/:project/merge_requests`
- GET `https://gitlab.example.com/api/v4/projects/:project/merge_requests/:number/versions`
- GET `https://gitlab.example.com/api/v4/projects/:project/merge_requests/:number/discussions`
- GET `https://gitlab.example.com/api/v4/projects/:project/merge_requests/:number/discussions/:discussion/notes/:note/award_emoji`
- GET `https://gitlab.example.com/api/v4/projects/:project/repository/branches`
- GET `https://gitlab.example.com/api/v4/:entity_type/:namespace/projects`
- PUT `https://gitlab.example.com/api/v4/groups/:namespace/hooks`
- POST `https://gitlab.example.com/api/v4/groups/:namespace/hooks`
- POST `https://gitlab.example.com/api/v4/projects/:project/hooks`
- POST `https://gitlab.example.com/api/v4/projects/:project/merge_requests/:number/discussions`
- POST `https://gitlab.example.com/api/v4/projects/:project/merge_requests/:number/discussions/:discussion/notes`
- PUT `https://gitlab.example.com/api/v4/projects/:project/merge_requests/:number/discussions/:discussion/notes/:note`
- PUT `https://gitlab.example.com/api/v4/projects/:project/merge_requests/:number/discussions/:discussion`

And if `allowCodeAccess` is set, additionally:

- GET `https://gitlab.example.com/api/v4/projects/:project/repository/files/*`
- GET `https://gitlab.example.com/api/v4/projects/:project/repository/commits`
- GET `https://gitlab.example.com/api/v4/projects/:project/repository/compare`
- POST `https://gitlab.example.com/api/v4/projects/:project/statuses/:commit`
- GET `https://gitlab.example.com/api/v4/personal_access_tokens/self`

### Bitbucket

Similarly, the `bitbucket` configuration section grants Semgrep access to leave MR comments.

```yaml
inbound:
  bitbucket:
    baseUrl: https://bitbucket.example.com/rest/api/latest
    token: ...
    allowCodeAccess: false # default is false, set to true to allow Semgrep to read file contents
```

Under the hood, this config adds these allowlist items:

- GET `https://bitbucket.example.com/rest/api/latest/projects/:project`
- GET `https://bitbucket.example.com/rest/api/latest/projects/:project/repos`
- GET `https://bitbucket.example.com/rest/api/latest/projects/:project/repo/:repo`
- GET `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/default-branch`
- GET `https://bitbucket.example.com/rest/api/latest/projects/:project/:repo/pull-requests`
- POST `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/pull-requests/:number/comments`
- GET `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/pull-requests/:number/comments/:comment`
- PUT `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/pull-requests/:number/comments/:comment`
- POST `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/pull-requests/:number/blocker-comments`
- GET `https://bitbucket.example.com/rest/api/latest/projects/:project/webhooks`
- POST `https://bitbucket.example.com/rest/api/latest/projects/:project/webhooks`
- PUT `https://bitbucket.example.com/rest/api/latest/projects/:project/webhooks/:webhook`
- DELETE `https://bitbucket.example.com/rest/api/latest/projects/:project/webhooks/:webhook`

And if `allowCodeAccess` is set, additionally:

- GET `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/browse/*`
- POST `https://bitbucket.example.com/rest/api/latest/projects/:project/repos/:repo/commit/:commit/builds`


### AzureDevops

Similarly, the `azuredevops` configuration section grants Semgrep access to azure devops.

```yaml
inbound:
  bitbucket:
    baseUrl: https://example@dev.azure.com/
    token: ...
    allowCodeAccess: false # default is false, set to true to allow Semgrep to read file contents
```

Under the hood, this config adds these allowlist items:

- GET `https://example@dev.azure.com/:namespace/_apis/connectionData`
- GET `https://example@dev.azure.com/:namespace/_apis/projects/:project`
- GET `https://example@dev.azure.com/:namespace/:project/_apis/git/repositories`
- GET `https://example@dev.azure.com/:namespace/:project/_apis/git/repositories/:repo`
- GET `https://example@dev.azure.com/:namespace/:project/_apis/git/repositories/:repo/pullRequests`
- GET `https://example@dev.azure.com/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/iterations`
- POST `https://example@dev.azure.com/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/threads`
- PATCH `https://example@dev.azure.com/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/threads`
- POST `https://example@dev.azure.com/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/threads/:threadId/comments`
- PATCH `https://example@dev.azure.com/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/threads/:threadId/comments/:commentId`
- GET `https://example@dev.azure.com/:namespace/:project/_apis/hooks/subscriptions`
- POST `https://example@dev.azure.com/:namespace/:project/_apis/hooks/subscriptions`
- PUT `https://example@dev.azure.com/:namespace/:project/_apis/hooks/subscriptions`
- GET `https://example@vsaex.dev.azure.com/:namespace/_apis/groupentitlements`

And if `allowCodeAccess` is set, additionally:

- GET `https://example@dev.azure.com/:namespace/:project/_apis/git/repositories/:repo/items`
- POST `https://example@dev.azure.com/:namespace/:project/_apis/git/repositories/:repo/commits/:commit/statuses`

### Allowlist

The `allowlist` configuration section provides finer-grained control over what HTTP requests are allowed to be forwarded out of the broker. The first matching allowlist item is used. No allowlist match means the request will not be proxied.

Examples:

```yaml
inbound:
  allowlist:
    # allow GET requests from http://example.com/foo (exact URL match)
    - url: http://example.com/foo
      methods: [GET]
    # allow GET or POST requests from any path on http://example.com
    - url: http://example.com/*
      methods: [GET, POST]
    # allow GET requests from a URL that looks like a GitHub Enterprise review comments URL, and add a bearer token to the request
    - url: http://example.com/api/v3/repos/:owner/:repo/pulls/:number/comments
      methods: [GET]
      setRequestHeaders:
        Authorization: "Bearer ...snip..."
```

### Real-world example

Here's an example of allowing PR comments for a GitHub Enterprise instance hosted on https://git.example.com. Replace `<GH TOKEN>` with a GitHub PAT.

```yaml
allowlist:
  - url: https://git.example.com/api/v3/repos/:owner/:repo
    methods: [GET]
    setRequestHeaders:
      Authorization: "Bearer <GH TOKEN>"
  - url: https://git.example.com/api/v3/repos/:owner/:repo/pulls
    methods: [GET]
    setRequestHeaders:
      Authorization: "Bearer <GH TOKEN>"
  - url: https://git.example.com/api/v3/repos/:owner/:repo/pulls/:number/comments
    methods: [POST]
    setRequestHeaders:
      Authorization: "Bearer <GH TOKEN>"
  - url: https://git.example.com/api/v3/repos/:owner/:repo/issues/:number/comments
    methods: [POST]
    setRequestHeaders:
      Authorization: "Bearer <GH TOKEN>"
```

### Logging

The `logging` configuration section allows you to set additional logging options for requests that are proxied through the broker.

```yaml
inbound:
  logging:
    logRequestBody: false # If true, the contents of any proxied HTTP request matching the allowlist will be logged in the request_body field in the proxy.request event
    logResponseBody: false # If true, the contents of any proxied HTTP response will be logged in the response_body field in the proxy.response event
```

Here's an example log output of `curl -X POST -H "Content-Type: application/json" "https://httpbin.org/anything" -d '{"foo": "bar"}'` being proxied through the network broker:

```
INFO[0006] request.start                                 client_ip="::1" id=1 method=POST path="/proxy/https://httpbin.org/anything" query= user_agent=curl/8.2.1
INFO[0006] proxy.request                                 allowlist_match="https://httpbin.org/*" client_ip="::1" destinationUrl="https://httpbin.org/anything" id=1 method=POST path="/proxy/https://httpbin.org/anything" query= request_body="{\"foo\": \"bar\"}" user_agent=curl/8.2.1
INFO[0006] proxy.response                                allowlist_match="https://httpbin.org/*" client_ip="::1" destinationUrl="https://httpbin.org/anything" id=1 method=POST path="/proxy/https://httpbin.org/anything" query= response_body="{\n  \"args\": {}, \n  \"data\": \"{\\\"foo\\\": \\\"bar\\\"}\", \n  \"files\": {}, \n  \"form\": {}, \n  \"headers\": {\n    \"Accept\": \"*/*\", \n    \"Accept-Encoding\": \"gzip\", \n    \"Content-Length\": \"14\", \n    \"Content-Type\": \"application/json\", \n    \"Host\": \"httpbin.org\", \n    \"User-Agent\": \"curl/8.2.1\", \n    \"X-Amzn-Trace-Id\": \"Root=1-650469a8-0032596526902b563d7e5ebc\"\n  }, \n  \"json\": {\n    \"foo\": \"bar\"\n  }, \n  \"method\": \"POST\", \n  \"origin\": \"::1, ...snip..., ...snip...\", \n  \"url\": \"https://httpbin.org/anything\"\n}\n" user_agent=curl/8.2.1
INFO[0006] request.response                              body_size=511 client_ip="::1" id=1 latency=341.905708ms method=POST path="/proxy/https://httpbin.org/anything" query= status_code=200 user_agent=curl/8.2.1
```

`logRequestBody` and `logResponseBody` can also be set on a per-allowlist basis:

```yaml
inbound:
  allowlist:
    - url: https://httpbin.org/*
      methods: [GET, POST, DELETE]
      logRequestBody: true
      logResponseBody: true
```

## Usage

The broker can be run in Kubernetes, as a bare Docker container, or simply as a standalone binary on a machine. If more than one instance of the broker is run at a time to manage availability, you may see some noise in the logs as the broker is not yet architected with this specific configuration in mind. However, it should still perform correctly without duplicating requests.

Config file(s) are passed to the app with `-c`:

```bash
semgrep-network-broker -c config.yaml
```

Multiple config files can be overlaid on top of each other by passing multiple `-c` args (ex. `semgrep-network-broker -c config1.yaml -c config2.yaml -c config3.yaml`). Note that while maps will be merged together, arrays will be _replaced_.

Requirements:

- internet access to `wireguard.semgrep.dev` on UDP port 51820

## Other Commands

### dump

`semgrep-network-broker dump` dumps the current config. This is useful to see what the result of multiple configurations overlays would result in

### genkey

`semgrep-network-broker genkey` generates a base64 private key to stdout

### pubkey

`semgrep-network-broker pubkey` generates a base64 public key for a given private key (via stdin)

### relay

`semgrep-network-broker relay` launches an HTTP server that relays request that match a certain rule.

```yaml
outbound:
  listenPort: 8080
  relay:
    test:
      destinationUrl: https://httpbin.org/anything
      jsonPath: "$.foo"
      equals:
        - bar
```

would result in requests addressed to http://localhost:8080/relay/test being relayed to https://httpbin.org/anything as long as the result of the jsonpath query `$.foo` executed on the request body results in the string `bar`.

Check out an example [here](./examples/github-pr-comment-relay.yaml) for how to use the relay for GitHub PR comments.

You can also define additional relay mappings via the `additionalConfigs` field:

```yaml
outbound:
  listenPort: 8080
  relay:
    test:
      destinationUrl: https://httpbin.org/anything
      jsonPath: "$.foo"
      equals:
        - bar
      additionalConfigs:
        - destinationUrl: htttps://example.com/fallback
```

The example above would relay traffic to https://httpbin.org/anything if the request body contains `{"foo": "bar"}`, otherwise, it'd relay traffic to `htttps://example.com/fallback`.
