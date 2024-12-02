package pkg

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

func GetRequestFields(c *gin.Context) log.Fields {
	if fields, ok := c.Value("fields").(log.Fields); ok {
		return fields
	}

	return log.Fields{
		"reqId": "not in request",
	}
}

func LoggerWithConfig(logger *log.Logger, notlogged []string) gin.HandlerFunc {
	var skip map[string]struct{}

	if length := len(notlogged); length > 0 {
		skip = make(map[string]struct{}, length)

		for _, path := range notlogged {
			skip[path] = struct{}{}
		}
	}

	var reqIdCounter uint64

	return func(c *gin.Context) {
		// Start timer
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		reqId := atomic.AddUint64(&reqIdCounter, 1)

		fields := log.Fields{
			"id":         reqId,
			"method":     c.Request.Method,
			"path":       path,
			"query":      raw,
			"client_ip":  c.ClientIP(),
			"user_agent": c.Request.UserAgent(),
		}

		requestLogger := logger.WithFields(fields)
		c.Set("fields", fields)

		_, shouldSkip := skip[path]

		if !shouldSkip {
			requestLogger.Info("request.start")
		}

		c.Header("X-SEMGREP-NETWORK-BROKER-REQ-ID", fmt.Sprint(reqId))

		// Process request
		c.Next()

		if !shouldSkip {
			requestLogger.WithField("latency", time.Since(start)).WithField("status_code", c.Writer.Status()).WithField("body_size", c.Writer.Size()).Info("request.response")
		}
	}
}

type MetricsHook struct {
	CounterFunc func(labelValues ...string) (prometheus.Counter, error)
}

func (mh *MetricsHook) Levels() []log.Level {
	return log.AllLevels
}

func (mh *MetricsHook) Fire(entry *log.Entry) error {
	if metric, err := mh.CounterFunc(entry.Level.String(), entry.Message); err == nil {
		metric.Inc()
	}
	return nil
}

func init() {
	h := &MetricsHook{
		CounterFunc: logEventsCounter.GetMetricWithLabelValues,
	}
	log.AddHook(h)
}
