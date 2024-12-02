package pkg

import (
	"fmt"
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var logEventsCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "network_broker_log_events_total",
	Help: "Counter of log events",
}, []string{"level", "event"})

var heartbeatCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "network_broker_heartbeat_total",
}, []string{"result"})

var heartbeatSuccessCounter = heartbeatCounter.WithLabelValues("success")
var heartbeatFailureCounter = heartbeatCounter.WithLabelValues("failure")

var heartbeatLastSuccessTimestamp = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "network_broker_heartbeat_last_success_timestamp_seconds",
}) // TODO: refactor heartbeat.go to be per-endpoint, and then include peer_endpoint as a label

var proxyInFlightGauge = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "network_broker_proxy_in_flight_requests",
})

var proxyCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "network_broker_proxy_requests_total",
}, []string{"allowlist", "method", "code"})

func StartMetrics(config *Config) error {
	if config.Metrics.Disabled {
		log.WithField("port", config.Metrics.Port).Info("external_metrics.disabled")
		return nil
	}

	prometheus.MustRegister(logEventsCounter, heartbeatCounter, heartbeatLastSuccessTimestamp, proxyInFlightGauge, proxyCounter)

	promHandler := promhttp.Handler()
	httpServer := &http.Server{Addr: fmt.Sprintf(":%d", config.Metrics.Port), Handler: promHandler}
	listener, err := net.Listen("tcp", httpServer.Addr)
	if err != nil {
		return fmt.Errorf("failed to start metrics server: %w", err)
	}
	go httpServer.Serve(listener)
	log.WithField("port", config.Metrics.Port).Info("external_metrics.started")

	return nil
}

func BuildInstrumentedRoundTripper(transport http.RoundTripper, allowlist string) (http.RoundTripper, error) {
	labels := prometheus.Labels{"allowlist": allowlist}
	counter, err := proxyCounter.CurryWith(labels)
	if err != nil {
		return nil, err
	}
	instrumentedTransport := promhttp.InstrumentRoundTripperInFlight(proxyInFlightGauge,
		promhttp.InstrumentRoundTripperCounter(counter, transport),
	)
	return instrumentedTransport, nil
}
