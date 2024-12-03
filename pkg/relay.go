package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"reflect"
	"strings"

	"github.com/PaesslerAG/jsonpath"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"gopkg.in/dealancer/validate.v2"
)

func GetRequestBodyJSON(body io.Reader) (map[string]interface{}, error) {
	var value = make(map[string]interface{})

	if body != nil {
		decoder := json.NewDecoder(body)

		if err := decoder.Decode(&value); err != nil {
			if err == io.EOF {
				return value, nil
			}
			return nil, fmt.Errorf("error decoding request body json: %v", err)
		}
	}

	return value, nil
}

func (config *FilteredRelayConfig) FindMatch(headers *http.Header, value map[string]interface{}) (*FilteredRelayConfig, bool, error) {
	bodyMatch := true

	if config.JSONPath != "" {
		result, err := jsonpath.Get(config.JSONPath, value)

		if err != nil {
			if strings.HasPrefix(err.Error(), "unknown key ") {
				result = ""
			} else {
				return config, false, fmt.Errorf("error evaluating jsonpath: %v", err)
			}
		}

		if reflect.TypeOf(result).Kind() != reflect.String {
			return config, false, fmt.Errorf("jsonpath result is not a string")
		}

		resultStr := result.(string)

		for _, val := range config.Equals {
			if resultStr != val {
				bodyMatch = false
				break
			}
		}
		for _, val := range config.HasPrefix {
			if !strings.HasPrefix(resultStr, val) {
				bodyMatch = false
				break
			}
		}
		for _, val := range config.Contains {
			if !strings.Contains(resultStr, val) {
				bodyMatch = false
				break
			}
		}
	}

	headerMatch := true

	for k, v := range config.HeaderEquals {
		if headers.Get(k) != v {
			headerMatch = false
			break
		}
	}

	for k, v := range config.HeaderNotEquals {
		if headers.Get(k) == v {
			headerMatch = false
			break
		}
	}

	if bodyMatch && headerMatch {
		return config, true, nil
	}

	for i := range config.AdditionalConfigs {
		inner_config, inner_match, inner_err := config.AdditionalConfigs[i].FindMatch(headers, value)
		if inner_match || inner_err != nil {
			return inner_config, inner_match, inner_err
		}
	}

	return config, false, nil
}

func (config *OutboundProxyConfig) Start() error {
	// ensure config is valid
	if err := validate.Validate(config); err != nil {
		return fmt.Errorf("invalid relay config: %v", err)
	}

	if len(config.Relay) == 0 {
		log.Warn("relay.no_configs")
		return nil
	}

	for k, v := range config.Relay {
		log.WithField("path", fmt.Sprintf("/relay/%v", k)).WithField("destinationUrl", v.DestinationURL).WithField("jsonPath", v.JSONPath).WithField("equals", v.Equals).WithField("hasPrefix", v.HasPrefix).WithField("contains", v.Contains).Info("relay.configured")
	}

	// setup http server
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(LoggerWithConfig(log.StandardLogger(), []string{}), gin.Recovery())

	// setup healthcheck
	r.GET(healthcheckPath, func(c *gin.Context) { c.JSON(http.StatusOK, "OK") })
	log.WithField("path", healthcheckPath).Info("healthcheck.configured")

	// setup http proxy
	r.Any("/relay/:name", func(c *gin.Context) {
		relayName := c.Param("name")
		logger := log.WithFields(GetRequestFields(c))

		relayConfig, ok := config.Relay[relayName]

		if !ok {
			logger.Warn("relay.not_found")
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("no such relay: %v", relayName)})
			return
		}

		buf := &bytes.Buffer{}
		buf.ReadFrom(c.Request.Body)
		defer c.Request.Body.Close()

		obj, err := GetRequestBodyJSON(bytes.NewReader(buf.Bytes()))
		if err != nil {
			logger.WithError(err).Warn("relay.parse_json")
		}

		filteredRelayConfig, match, err := relayConfig.FindMatch(&c.Request.Header, obj)
		if err != nil {
			logger.WithError(err).Info("relay.match_err")
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("matching error: %v", err)})
			return
		}

		if config.Logging.LogRequestBody || filteredRelayConfig.LogRequestBody {
			logger = logger.WithField("request_body", buf.String())
		}

		if config.Logging.LogRequestHeaders {
			logger = logger.WithField("request_headers", c.Request.Header)
		}

		if !match {
			logger.Info("relay.no_match")
			c.Header("X-Semgrep-Network-Broker-Relay-Match", "0")
			c.JSON(http.StatusOK, gin.H{"result": "no match"})
			return
		}

		c.Header("X-Semgrep-Network-Broker-Relay-Match", "1")

		logger = logger.WithField("destinationUrl", filteredRelayConfig.DestinationURL)

		destinationUrl, err := url.Parse(filteredRelayConfig.DestinationURL) // TODO: precompute this
		if err != nil {
			logger.WithError(err).Warn("relay.destination_url_parse")
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("url parser error: %v", err)})
			return
		}

		logger.Info("relay.proxy_request")
		proxy := httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.Body = io.NopCloser(buf)
				req.URL = destinationUrl
				req.Host = destinationUrl.Host
			},
			ModifyResponse: func(resp *http.Response) error {
				respLogger := logger
				if config.Logging.LogResponseBody || filteredRelayConfig.LogResponseBody {
					respBuf := &bytes.Buffer{}
					respBuf.ReadFrom(resp.Body)
					defer resp.Body.Close()
					resp.Body = io.NopCloser(respBuf)
					respLogger = logger.WithField("response_body", respBuf.String())
				}
				if config.Logging.LogResponseHeaders || filteredRelayConfig.LogResponseHeaders {
					respLogger = respLogger.WithField("response_headers", resp.Header)
				}
				respLogger.Info("relay.proxy_response")
				return nil
			},
		}
		proxy.ServeHTTP(c.Writer, c.Request)
	})

	// its showtime!
	addr := fmt.Sprintf(":%v", config.ListenPort)
	go r.Run(addr)
	log.WithField("listen", addr).Info("relay.start")

	return nil
}
