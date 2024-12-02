package pkg

import (
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func (config *HeartbeatConfig) Start(tnet *netstack.Net, userAgent string) (func(), error) {
	ticker := time.NewTicker(time.Duration(config.IntervalSeconds) * time.Second)
	done := make(chan bool)
	failures := -1

	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
		Timeout: time.Duration(config.TimeoutSeconds) * time.Second,
	}

	execute := func() bool {
		logger := log.WithField("heartbeat_url", config.URL)
		req, err := http.NewRequest("GET", config.URL, nil)
		if err != nil {
			logger.Panic(fmt.Errorf("invalid heartbeat request: %v", err))
		}
		if userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}
		resp, err := httpClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			failures++
			if config.PanicAfterFailureCount > 0 && failures >= config.PanicAfterFailureCount {
				log.Panicf("Heartbeat failed %v times in a row", failures)
			}
			if err != nil {
				log.WithField("failure_count", failures).WithError(err).Warn("heartbeat.failure")
			} else {
				log.WithField("failure_count", failures).WithField("status_code", resp.StatusCode).Warn("heartbeat.failure")
			}
			heartbeatFailureCounter.Inc()
			return false
		} else {
			if failures != 0 {
				log.WithField("message", "Established connectivity with Semgrep").Info("heartbeat.success")
			}
			log.Debug("heartbeat.success")
			failures = 0
			heartbeatSuccessCounter.Inc()
			heartbeatLastSuccessTimestamp.SetToCurrentTime()
			return true
		}
	}

	success := execute()
	if config.FirstHeartbeatMustSucceed && !success {
		return nil, fmt.Errorf("first heartbeat did not succeed")
	}
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				execute()
			}
		}
	}()

	return func() {
		done <- true
	}, nil
}
