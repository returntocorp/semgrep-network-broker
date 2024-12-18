package pkg

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"

	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	log "github.com/sirupsen/logrus"

	"github.com/mcuadros/go-defaults"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

type Base64String []byte

func (bs Base64String) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(bs))
}

type SensitiveBase64String []byte

const RedactedString = "REDACTED"

func (sbs SensitiveBase64String) String() string {
	return RedactedString
}

func (sbs SensitiveBase64String) MarshalJSON() ([]byte, error) {
	return json.Marshal(sbs.String())
}

var base64StringType = reflect.TypeOf(Base64String(nil))
var sensitiveBase64StringType = reflect.TypeOf(SensitiveBase64String(nil))

func base64StringDecodeHook(
	f reflect.Type,
	t reflect.Type,
	data interface{}) (interface{}, error) {
	if f.Kind() != reflect.String {
		return data, nil
	}

	if t != base64StringType && t != sensitiveBase64StringType {
		return data, nil
	}

	bytes, err := base64.StdEncoding.DecodeString(data.(string))

	if err != nil {
		return nil, err
	}

	if t == sensitiveBase64StringType {
		return SensitiveBase64String(bytes), err
	} else {
		return Base64String(bytes), err
	}
}

type WireguardPeer struct {
	resolvedEndpoint            string
	PublicKey                   Base64String `mapstructure:"publicKey" json:"publicKey" validate:"empty=false"`
	Endpoint                    string       `mapstructure:"endpoint" json:"endpoint"`
	AllowedIps                  string       `mapstructure:"allowedIps" json:"allowedIps" validate:"format=cidr"`
	PersistentKeepaliveInterval int          `mapstructure:"persistentKeepaliveInterval" json:"persistentKeepaliveInterval" validate:"gt=0" default:"20"`
	DisablePersistentKeepalive  bool         `mapstructure:"disablePersistentKeepalive" json:"disablePersistentKeepalive"`
}

type WireguardBase struct {
	LocalAddress                 string                `mapstructure:"localAddress" json:"localAddress" validate:"format=ip"`
	Dns                          []string              `mapstructure:"dns" json:"dns" validate:"empty=true > format=ip"`
	Mtu                          int                   `mapstructure:"mtu" json:"mtu" validate:"gte=0" default:"1420"`
	PrivateKey                   SensitiveBase64String `mapstructure:"privateKey" json:"privateKey" validate:"empty=false"`
	ListenPort                   int                   `mapstructure:"listenPort" json:"listenPort" validate:"gte=0"`
	Peers                        []WireguardPeer       `mapstructure:"peers" json:"peers" validate:"empty=false"`
	Verbose                      bool                  `mapstructure:"verbose" json:"verbose"`
	DisablePeerSettingsDnsLookup bool                  `mapstructure:"disablePeerSettingsDnsLookup" json:"disablePeerSettingsDnsLookup"`
}

type BitTester interface {
	Test(i uint) bool
}

type BitSet uint16

func (bs BitSet) Test(i uint) bool {
	return bs&(1<<i) != 0
}

func (bs *BitSet) Set(i uint) error {
	if i >= 16 {
		return fmt.Errorf("bitset limited to 16 bits")
	}
	*bs = *bs | (1 << i)
	return nil
}

type HttpMethods BitSet

func (methods HttpMethods) Test(i uint) bool {
	return BitSet(methods).Test(i)
}

const (
	MethodUnknown uint = iota
	MethodGet
	MethodHead
	MethodPost
	MethodPut
	MethodPatch
	MethodDelete
	MethodConnect
	MethodOptions
	MethodTrace
)

func LookupHttpMethod(method string) uint {
	switch strings.ToUpper(method) {
	case "GET":
		return MethodGet
	case "HEAD":
		return MethodHead
	case "POST":
		return MethodPost
	case "PUT":
		return MethodPut
	case "PATCH":
		return MethodPatch
	case "DELETE":
		return MethodDelete
	case "CONNECT":
		return MethodConnect
	case "TRACE":
		return MethodTrace
	}
	return MethodUnknown
}

func ParseHttpMethods(methods []string) HttpMethods {
	bs := BitSet(0)

	for _, method := range methods {
		bs.Set(LookupHttpMethod(method))
	}

	return HttpMethods(bs)
}

func httpMethodsDecodeHook(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
	if f.Kind() != reflect.Slice {
		return data, nil
	}
	if t != reflect.TypeOf(HttpMethods(0)) {
		return data, nil
	}
	if f.Elem().Kind() == reflect.String {
		return ParseHttpMethods(data.([]string)), nil
	}

	methods := make([]string, len(data.([]interface{})))
	for i, method := range data.([]interface{}) {
		methodString, ok := method.(string)
		if !ok {
			return nil, fmt.Errorf("item at index %v is not a string", i)
		}
		methods = append(methods, methodString)
	}

	return ParseHttpMethods(methods), nil
}

type graphQlRequest struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
}

func (config *InboundProxyConfig) validateGraphQLRequest(body []byte, filter *GraphQLFilter) error {
	if filter == nil {
		return nil
	}

	var req graphQlRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return fmt.Errorf("invalid GitHub GraphQL request JSON: %v", err)
	}

	doc, err := parser.Parse(parser.ParseParams{
		Source: req.Query,
	})
	if err != nil {
		return fmt.Errorf("graphql query is unparseable: %v", err)
	}

	// GitHub GraphQL requests typically have a single operation
	var foundOperation *ast.OperationDefinition
	for _, def := range doc.Definitions {
		if opDef, ok := def.(*ast.OperationDefinition); ok {
			foundOperation = opDef
			break
		}
	}

	if foundOperation == nil {
		return fmt.Errorf("no GraphQL operation found")
	}

	opType := string(foundOperation.Operation)
	opName := ""
	if foundOperation.Name != nil {
		opName = foundOperation.Name.Value
	}

	// If operation name is provided in the request, it must match the query
	if req.OperationName != "" && opName != req.OperationName {
		return fmt.Errorf("operation name mismatch between request and query")
	}

	// Validate against allowed operations
	allowedOps, exists := filter.AllowedOperations[opType]
	if !exists {
		return fmt.Errorf("GitHub GraphQL operation type '%s' not allowed", opType)
	}

	if opName == "" {
		return fmt.Errorf("GitHub GraphQL operations must be named")
	}

	for _, allowedOp := range allowedOps {
		if allowedOp == opName {
			return nil // Operation is allowed
		}
	}

	return fmt.Errorf("GitHub GraphQL %s operation '%s' not allowed", opType, opName)
}

type GraphQLFilter struct {
	AllowedOperations map[string][]string `validate:"required"` // map[operationType][]operationName
}
type AllowlistItem struct {
	URL                   string            `mapstructure:"url" json:"url"`
	Methods               HttpMethods       `mapstructure:"methods" json:"methods"`
	SetRequestHeaders     map[string]string `mapstructure:"setRequestHeaders" json:"setRequestHeaders"`
	RemoveResponseHeaders []string          `mapstructure:"removeResponseHeaders" json:"removeRequestHeaders"`
	LogRequestBody        bool              `mapstructure:"logRequestBody" json:"logRequestBody"`
	LogRequestHeaders     bool              `mapstructure:"logRequestHeaders" json:"logRequestHeaders"`
	LogResponseBody       bool              `mapstructure:"logResponseBody" json:"logResponseBody"`
	LogResponseHeaders    bool              `mapstructure:"logResponseHeaders" json:"logResponseHeaders"`
	GraphQLData           *GraphQLFilter    `mapstructure:"githubGraphQL" json:"githubGraphQL"`
}

type Allowlist []AllowlistItem

type LoggingConfig struct {
	SkipPaths          []string `mapstructure:"skipPaths" json:"skipPaths"`
	LogRequestBody     bool     `mapstructure:"logRequestBody" json:"logRequestBody"`
	LogRequestHeaders  bool     `mapstructure:"logRequestHeaders" json:"logRequestHeaders"`
	LogResponseBody    bool     `mapstructure:"logResponseBody" json:"logResponseBody"`
	LogResponseHeaders bool     `mapstructure:"logResponseHeaders" json:"logResponseHeaders"`
}

type HeartbeatConfig struct {
	URL                       string `mapstructure:"url" json:"url" validate:"format=url"`
	IntervalSeconds           int    `mapstructure:"intervalSeconds" json:"intervalSeconds" validate:"gte=30" default:"60"`
	TimeoutSeconds            int    `mapstructure:"timeoutSeconds" json:"timeoutSeconds" validate:"gt=0" default:"5"`
	PanicAfterFailureCount    int    `mapstructure:"panicAfterFailureCount" json:"panicAfterFailureCount" validate:"gte=0"`
	FirstHeartbeatMustSucceed bool   `mapstructure:"firstHeartbeatMustSucceed" json:"firstHeartbeatMustSucceed"`
}

type GitHub struct {
	BaseURL         string `mapstructure:"baseUrl" json:"baseUrl"`
	Token           string `mapstructure:"token" json:"token"`
	AllowCodeAccess bool   `mapstructure:"allowCodeAccess" json:"allowCodeAccess"`
}

type GitLab struct {
	BaseURL         string `mapstructure:"baseUrl" json:"baseUrl"`
	Token           string `mapstructure:"token" json:"token"`
	AllowCodeAccess bool   `mapstructure:"allowCodeAccess" json:"allowCodeAccess"`
}

type BitBucket struct {
	BaseURL         string `mapstructure:"baseUrl" json:"baseUrl"`
	Token           string `mapstructure:"token" json:"token"`
	AllowCodeAccess bool   `mapstructure:"allowCodeAccess" json:"allowCodeAccess"`
}

type AzureDevOps struct {
	BaseURL         string `mapstructure:"baseUrl" json:"baseUrl"`
	Token           string `mapstructure:"token" json:"token"`
	AllowCodeAccess bool   `mapstructure:"allowCodeAccess" json:"allowCodeAccess"`
}

type HttpClientConfig struct {
	AdditionalCACerts []string `mapstructure:"additionalCACerts" json:"additionalCACerts"`
}

type InboundProxyConfig struct {
	Wireguard       WireguardBase    `mapstructure:"wireguard" json:"wireguard"`
	Allowlist       Allowlist        `mapstructure:"allowlist" json:"allowlist"`
	ProxyListenPort int              `mapstructure:"proxyListenPort" json:"proxyListenPort" validate:"gte=0" default:"80"`
	Logging         LoggingConfig    `mapstructure:"logging" json:"logging"`
	Heartbeat       HeartbeatConfig  `mapstructure:"heartbeat" json:"heartbeat"`
	GitHub          *GitHub          `mapstructure:"github" json:"github"`
	GitLab          *GitLab          `mapstructure:"gitlab" json:"gitlab"`
	BitBucket       *BitBucket       `mapstructure:"bitbucket" json:"bitbucket"`
	AzureDevOps     *AzureDevOps     `mapstructure:"azuredevops" json:"azuredevops"`
	HttpClient      HttpClientConfig `mapstructure:"httpClient" json:"httpClient"`
}

type FilteredRelayConfig struct {
	DestinationURL    string                `mapstructure:"destinationUrl"`
	JSONPath          string                `mapstructure:"jsonPath"`
	Contains          []string              `mapstructure:"contains"`
	Equals            []string              `mapstructure:"equals"`
	HasPrefix         []string              `mapstructure:"hasPrefix"`
	HeaderEquals      map[string]string     `mapstructure:"headerEquals"`
	HeaderNotEquals   map[string]string     `mapstructure:"headerNotEquals"`
	AdditionalConfigs []FilteredRelayConfig `mapstructure:"additionalConfigs"` // this is awful, but we can refactor this in the near future

	LogRequestBody     bool `mapstructure:"logRequestBody" json:"logRequestBody"`
	LogRequestHeaders  bool `mapstructure:"logRequestHeaders" json:"logRequestHeaders"`
	LogResponseBody    bool `mapstructure:"logResponseBody" json:"logResponseBody"`
	LogResponseHeaders bool `mapstructure:"logResponseHeaders" json:"logResponseHeaders"`
}

type OutboundProxyConfig struct {
	Relay      map[string]FilteredRelayConfig `mapstructure:"relay" json:"relay"`
	Logging    LoggingConfig                  `mapstructure:"logging" json:"logging"`
	ListenPort int                            `mapstructure:"listenPort" json:"listenPort" validate:"gte=0" default:"8080"`
}

type MetricsConfig struct {
	Disabled                      bool   `mapstructure:"disabled" json:"disabled"`
	Addr                          string `mapstructure:"addr" json:"addr" default:":9000"`
	HealthcheckGracePeriodSeconds int    `mapstructure:"healthcheckGracePeriodSeconds" json:"healthcheckGracePeriodSeconds" validate:"gte=0" default:"10"`
}

type Config struct {
	Inbound  InboundProxyConfig  `mapstructure:"inbound" json:"inbound"`
	Outbound OutboundProxyConfig `mapstructure:"outbound" json:"outbound"`
	Metrics  MetricsConfig       `mapstructure:"metrics" json:"metrics"`
}

func LoadConfig(configFiles []string, deploymentId int) (*Config, error) {
	config := new(Config)

	// Step 1: Apply config values encoded in broker token (if provided)
	tokenString, err := LoadTokenFromEnv()
	if err != nil {
		return config, fmt.Errorf("failed to load token: %v", err)
	}

	if tokenString != "" {
		token, err := ParseBrokerToken(tokenString)
		if err != nil {
			return config, fmt.Errorf("failed to parse token: %v", err)
		}

		config.Inbound.Wireguard.LocalAddress = token.WireguardCredential.LocalAddress
		config.Inbound.Wireguard.PrivateKey = token.WireguardCredential.PrivateKey
	}

	// Step 2: Apply config values from semgrep.dev/api/broker/{deployment_id}/default-config, if a deployment ID is provided
	// NOTE: we will be phasing this out in favor of retrieving default configs from the broker gateway
	if deploymentId > 0 {
		hostname := os.Getenv("SEMGREP_HOSTNAME")
		if hostname == "" {
			hostname = "semgrep.dev"
		}
		url := url.URL{
			Scheme: "https",
			Host:   hostname,
			Path:   fmt.Sprintf("/api/broker/%d/default-config", deploymentId),
		}

		resp, err := http.Get(url.String())
		if err != nil {
			return nil, fmt.Errorf("failed to request default broker config from %v: %v", hostname, err)
		}

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("failed to request default config from %s: HTTP %v", url.String(), resp.StatusCode)
		}

		f, err := os.CreateTemp("", "default-config*.json")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file to store default config: %v", err)
		}
		defer func() {
			f.Close()
			os.Remove(f.Name())
		}()

		io.Copy(f, resp.Body)
		defer resp.Body.Close()

		viper.SetConfigFile(f.Name())
		if err := viper.MergeInConfig(); err != nil {
			return nil, fmt.Errorf("failed to merge config file '%s': %v", f.Name(), err)
		}
	}

	// Step 3: Load config files passed via command line
	for i := range configFiles {
		viper.SetConfigFile(configFiles[i])
		if err := viper.MergeInConfig(); err != nil {
			return nil, fmt.Errorf("failed to merge config file '%s': %v", configFiles[i], err)
		}
	}
	if err := viper.Unmarshal(config, func(dc *mapstructure.DecoderConfig) {
		dc.DecodeHook = mapstructure.ComposeDecodeHookFunc(base64StringDecodeHook, httpMethodsDecodeHook)
	}); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	// Step 4: Resolve TXT record(s) of wireguard peers, fill in config values if not set in a config file
	if !config.Inbound.Wireguard.DisablePeerSettingsDnsLookup {
		for i := range config.Inbound.Wireguard.Peers {
			peer := &config.Inbound.Wireguard.Peers[i]

			endpoint := peer.Endpoint
			if i := strings.Index(endpoint, ":"); i >= 0 {
				endpoint = endpoint[0:i]
			}

			if net.ParseIP(endpoint) != nil {
				continue // cant look up TXT record for IPs
			}

			logger := log.WithField("endpoint", endpoint)

			records, err := net.LookupTXT(endpoint)
			if err != nil {
				var dnsError *net.DNSError
				if errors.As(err, &dnsError) && dnsError.IsNotFound {
					logger.WithError(dnsError).Warn("txt_lookup.failed")
				} else {
					return nil, fmt.Errorf("failed to lookup TXT records for %v: %w", endpoint, err)
				}
			}

			for _, record := range records {
				i := strings.Index(record, "=")
				if i < 0 {
					continue // skip any records that arent key=value formatted
				}
				key, value := record[0:i], record[i+1:]
				switch key {
				case "wireguardAllowedIps":
					if peer.AllowedIps == "" {
						peer.AllowedIps = value
					}
				case "wireguardPublicKey":
					if peer.PublicKey == nil {
						decoded_value, err := base64.StdEncoding.DecodeString(value)
						if err != nil {
							return nil, fmt.Errorf("failed to decode pubkey %v: %w", value, err)
						}
						peer.PublicKey = Base64String(decoded_value)
					}
				case "heartbeat":
					if config.Inbound.Heartbeat.URL == "" {
						config.Inbound.Heartbeat.URL = value
					}
				default:
					logger.WithField("record_key", key).WithField("record_value", value).Warn("txt_lookup.unrecognized_key")
				}
			}
		}
	}

	// Step 5: Apply default values to any remaining unset config fields
	defaults.SetDefaults(config)

	if config.Inbound.GitHub != nil {
		gitHub := config.Inbound.GitHub

		gitHubBaseUrl, err := url.Parse(gitHub.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse github base URL: %v", err)
		}
		gitHubBaseUrlGraphQL, err := url.Parse(strings.Replace(gitHub.BaseURL, "/api/v3", "/api/graphql", 1))
		if err != nil {
			return nil, fmt.Errorf("failed to parse github GraphQL base URL: %v", err)
		}

		var headers map[string]string
		if gitHub.Token != "" {
			headers = map[string]string{
				"Authorization": fmt.Sprintf("Bearer %v", gitHub.Token),
			}
		} else {
			headers = map[string]string{}
		}

		config.Inbound.Allowlist = append(config.Inbound.Allowlist,
			// repo info
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// PR info
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/pulls").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// post PR comment
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/pulls/:number/comments").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// post issue comment
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:owner/:repo/issues/:number/comments").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// check app installation for an org
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/orgs/:org/installation").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// check repos for an org
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/orgs/:org/repos").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// alternative: check repos for an installation
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/installation/repositories").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// check app installation for a personal account
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/users/:user/installation").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// check repo installation for a personal account
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/users/:user/installation/repositories").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// initiate app installation
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/app-manifests/:code/conversions").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// get app installation
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/app").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/app/installations/:id/access_tokens").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:org/:repo/actions/secrets/SEMGREP_APP_TOKEN").String(),
				Methods:           ParseHttpMethods([]string{"PUT"}),
				SetRequestHeaders: headers,
			},
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:org/:repo/actions/secrets/public-key").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			AllowlistItem{
				URL:               gitHubBaseUrl.JoinPath("/repos/:org/:repo/contents/.github/workflows/semgrep.yml").String(),
				Methods:           ParseHttpMethods([]string{"GET", "PUT"}),
				SetRequestHeaders: headers,
			},
			// Graphql API with specific operations
			AllowlistItem{
				URL:               gitHubBaseUrlGraphQL.String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
				GraphQLData: &GraphQLFilter{
					AllowedOperations: map[string][]string{
						"query": {
							"GetBlameDetails",
						},
						"mutation": {
							"resolveReviewThread",
							"unresolveReviewThread",
						},
					},
				},
			},
		)

		if config.Inbound.GitHub.AllowCodeAccess {
			config.Inbound.Allowlist = append(config.Inbound.Allowlist,
				// get contents of file
				AllowlistItem{
					URL:               gitHubBaseUrl.JoinPath("/repos/:repo/contents/:filepath").String(),
					Methods:           ParseHttpMethods([]string{"GET"}),
					SetRequestHeaders: headers,
				},
				// Commits
				AllowlistItem{
					URL:               gitHubBaseUrl.JoinPath("/repos/:repo/commits").String(),
					Methods:           ParseHttpMethods([]string{"GET"}),
					SetRequestHeaders: headers,
				},
			)
		}
	}

	if config.Inbound.GitLab != nil {
		gitLab := config.Inbound.GitLab

		gitLabBaseUrl, err := url.Parse(gitLab.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse gitlab base URL: %v", err)
		}

		var headers map[string]string
		if gitLab.Token != "" {
			headers = map[string]string{
				"PRIVATE-TOKEN": gitLab.Token,
			}
		} else {
			headers = map[string]string{}
		}

		config.Inbound.Allowlist = append(config.Inbound.Allowlist,
			// Group webhooks
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/groups/:namespace/hooks").String(),
				Methods:           ParseHttpMethods([]string{"GET", "POST", "PUT"}),
				SetRequestHeaders: headers,
			},
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/groups/:namespace/hooks/:hook").String(),
				Methods:           ParseHttpMethods([]string{"DELETE"}),
				SetRequestHeaders: headers,
			},
			// Group info
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/groups/:namespace").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// repo info
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// Repo webhooks
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/hooks").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/hooks/:hook").String(),
				Methods:           ParseHttpMethods([]string{"DELETE"}),
				SetRequestHeaders: headers,
			},
			// Get a group member
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/groups/:namespace/members/all/:user").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// Get a repo member
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/members/all/:user").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// MR info
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/merge_requests").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// MR versions
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/merge_requests/:number/versions").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// Projects
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/:entity_type/:namespace/projects").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// Branches
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/repository/branches").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// post MR comment
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/merge_requests/:number/discussions").String(),
				Methods:           ParseHttpMethods([]string{"GET", "POST"}),
				SetRequestHeaders: headers,
			},
			// post MR comment reply
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/merge_requests/:number/discussions/:discussion/notes").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// update MR comment
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/merge_requests/:number/discussions/:discussion/notes/:note").String(),
				Methods:           ParseHttpMethods([]string{"PUT"}),
				SetRequestHeaders: headers,
			},
			// resolve MR comment
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/merge_requests/:number/discussions/:discussion").String(),
				Methods:           ParseHttpMethods([]string{"PUT"}),
				SetRequestHeaders: headers,
			},
			// Get reactions to comments
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/projects/:project/merge_requests/:number/discussions/:discussion/notes/:note/award_emoji").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// Get scm token info
			AllowlistItem{
				URL:               gitLabBaseUrl.JoinPath("/personal_access_tokens/self").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
		)

		if config.Inbound.GitLab.AllowCodeAccess {
			config.Inbound.Allowlist = append(config.Inbound.Allowlist,
				// get contents of file
				AllowlistItem{
					URL:               gitLabBaseUrl.JoinPath("/projects/:project/repository/files/:filepath").String(),
					Methods:           ParseHttpMethods([]string{"GET"}),
					SetRequestHeaders: headers,
				},
				// Commits
				AllowlistItem{
					URL:               gitLabBaseUrl.JoinPath("/projects/:project/repository/commits").String(),
					Methods:           ParseHttpMethods([]string{"GET"}),
					SetRequestHeaders: headers,
				},
				// Compare branches
				AllowlistItem{
					URL:               gitLabBaseUrl.JoinPath("/projects/:project/repository/compare").String(),
					Methods:           ParseHttpMethods([]string{"GET"}),
					SetRequestHeaders: headers,
				},
				// Update commit status
				AllowlistItem{
					URL:               gitLabBaseUrl.JoinPath("/projects/:project/statuses/:commit").String(),
					Methods:           ParseHttpMethods([]string{"GET"}),
					SetRequestHeaders: headers,
				},
			)
		}
	}

	if config.Inbound.BitBucket != nil {
		bitBucket := config.Inbound.BitBucket

		bitBucketBaseUrl, err := url.Parse(bitBucket.BaseURL)

		if err != nil {
			return nil, fmt.Errorf("failed to parse bitbucket base URL: %v", err)
		}

		var headers map[string]string
		if bitBucket.Token != "" {
			headers = map[string]string{
				"Authorization": fmt.Sprintf("Bearer %v", bitBucket.Token),
			}
		} else {
			headers = map[string]string{}
		}

		config.Inbound.Allowlist = append(config.Inbound.Allowlist,
			// project info
			AllowlistItem{
				URL:               bitBucketBaseUrl.JoinPath("/projects/:project").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// get repos
			AllowlistItem{
				URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// repo info
			AllowlistItem{
				URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// default branch
			AllowlistItem{
				URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/default-branch").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// pull requests
			AllowlistItem{
				URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/pull-requests").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// post PR comment
			AllowlistItem{
				URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/pull-requests/:number/comments").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// get and update PR comment
			AllowlistItem{
				URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/pull-requests/:number/comments/:comment").String(),
				Methods:           ParseHttpMethods([]string{"GET", "PUT"}),
				SetRequestHeaders: headers,
			},
			// post blockerPR comment
			AllowlistItem{
				URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/pull-requests/:number/blocker-comments").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			// namespace webhooks
			AllowlistItem{
				URL:               bitBucketBaseUrl.JoinPath("/projects/:project/webhooks").String(),
				Methods:           ParseHttpMethods([]string{"GET", "POST"}),
				SetRequestHeaders: headers,
			},
			AllowlistItem{
				URL:               bitBucketBaseUrl.JoinPath("/projects/:project/webhooks/:webhook").String(),
				Methods:           ParseHttpMethods([]string{"PUT", "DELETE"}),
				SetRequestHeaders: headers,
			},
		)

		if config.Inbound.BitBucket.AllowCodeAccess {
			// get contents of file
			config.Inbound.Allowlist = append(config.Inbound.Allowlist,
				AllowlistItem{
					URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/browse/:filepath").String(),
					Methods:           ParseHttpMethods([]string{"GET"}),
					SetRequestHeaders: headers,
				},
				// update commit status
				AllowlistItem{
					URL:               bitBucketBaseUrl.JoinPath("/projects/:project/repos/:repo/commit/:commit/builds").String(),
					Methods:           ParseHttpMethods([]string{"POST"}),
					SetRequestHeaders: headers,
				},
			)

		}
	}

	if config.Inbound.AzureDevOps != nil {
		azureDevOps := config.Inbound.AzureDevOps

		azureDevOpsBaseUrl, err := url.Parse(azureDevOps.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse azure devops base URL: %v", err)
		}

		vsaexBaseUrl := strings.Replace(azureDevOps.BaseURL, "dev.azure.com", "vsaex.dev.azure.com", 1)
		vsaexUrl, err := url.Parse(vsaexBaseUrl)
		if err != nil {
			return nil, fmt.Errorf("failed to parse azure devops vsaex base URL: %v", err)
		}

		var headers map[string]string
		if azureDevOps.Token != "" {
			headers = map[string]string{
				"Authorization": fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(azureDevOps.Token))),
			}
		} else {
			headers = map[string]string{}
		}

		config.Inbound.Allowlist = append(config.Inbound.Allowlist,
			// Check organization access
			AllowlistItem{
				URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/_apis/connectionData").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// Namespace info
			AllowlistItem{
				URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/_apis/projects/:project").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// get repos
			AllowlistItem{
				URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// repo info
			AllowlistItem{
				URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// PR info
			AllowlistItem{
				URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/pullRequests").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// get pull request iterations
			AllowlistItem{
				URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/iterations").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
			// post and update PR comment
			AllowlistItem{
				URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/threads").String(),
				Methods:           ParseHttpMethods([]string{"POST", "PATCH"}),
				SetRequestHeaders: headers,
			},
			// post and update PR comment reply
			AllowlistItem{
				URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/threads/:threadId/comments").String(),
				Methods:           ParseHttpMethods([]string{"POST"}),
				SetRequestHeaders: headers,
			},
			AllowlistItem{
				URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/pullRequests/:number/threads/:threadId/comments/:commentId").String(),
				Methods:           ParseHttpMethods([]string{"PATCH"}),
				SetRequestHeaders: headers,
			},
			// namespace webhooks
			AllowlistItem{
				URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/hooks/subscriptions").String(),
				Methods:           ParseHttpMethods([]string{"GET", "POST", "PUT"}),
				SetRequestHeaders: headers,
			},
			// list teams
			AllowlistItem{
				URL:               vsaexUrl.JoinPath("/:namespace/_apis/groupentitlements").String(),
				Methods:           ParseHttpMethods([]string{"GET"}),
				SetRequestHeaders: headers,
			},
		)

		if config.Inbound.AzureDevOps.AllowCodeAccess {
			config.Inbound.Allowlist = append(config.Inbound.Allowlist,
				// get file content
				AllowlistItem{
					URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/items").String(),
					Methods:           ParseHttpMethods([]string{"GET"}),
					SetRequestHeaders: headers,
				},
				// update commit status
				AllowlistItem{
					URL:               azureDevOpsBaseUrl.JoinPath("/:namespace/:project/_apis/git/repositories/:repo/commits/:commit/statuses").String(),
					Methods:           ParseHttpMethods([]string{"POST"}),
					SetRequestHeaders: headers,
				},
			)
		}
	}

	return config, nil
}
