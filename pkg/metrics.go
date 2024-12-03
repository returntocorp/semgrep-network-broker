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
	Help: "Total number of log events",
}, []string{"level", "event"})

var heartbeatCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "network_broker_heartbeat_total",
	Help: "Total number of heartbeat attempts",
}, []string{"result"})

var heartbeatSuccessCounter = heartbeatCounter.WithLabelValues("success")
var heartbeatFailureCounter = heartbeatCounter.WithLabelValues("failure")

var heartbeatLastSuccessTimestamp = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "network_broker_heartbeat_last_success_timestamp_seconds",
	Help: "Timestamp of last successful heartbeat attempt in seconds",
}) // TODO: refactor heartbeat.go to be per-endpoint, and then include peer_endpoint as a label

var proxyInFlightGauge = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "network_broker_proxy_in_flight_requests",
	Help: "Number of in-flight proxy requests",
})

var proxyCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "network_broker_proxy_requests_total",
	Help: " Total number of proxy requests",
}, []string{"allowlist", "method", "code"})

func StartMetrics(config *Config) error {
	if config.Metrics.Disabled {
		log.WithField("addr", config.Metrics.Addr).Info("external_metrics.disabled")
		return nil
	}

	prometheus.MustRegister(logEventsCounter, heartbeatCounter, heartbeatLastSuccessTimestamp, proxyInFlightGauge, proxyCounter)

	promHandler := promhttp.Handler()
	httpServer := &http.Server{Addr: config.Metrics.Addr, Handler: promHandler}
	listener, err := net.Listen("tcp", httpServer.Addr)
	if err != nil {
		return fmt.Errorf("failed to start external metrics server: %w", err)
	}
	go httpServer.Serve(listener)
	log.WithField("addr", config.Metrics.Addr).Info("external_metrics.started")

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
