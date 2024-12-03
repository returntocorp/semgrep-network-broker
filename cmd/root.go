/*
Copyright © 2022 Tom Petr, r2c <tom@r2c.dev>
*/
package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/semgrep/semgrep-network-broker/build"
	"github.com/semgrep/semgrep-network-broker/pkg"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var configFiles []string
var jsonLog bool
var deploymentId int

var rootCmd = &cobra.Command{
	Use:     "semgrep-network-broker",
	Version: fmt.Sprintf("%s (%s at %s)", build.Version, build.Revision, build.BuildTime),
	Short:   "semgrep-network-broker brokers network access to and from the Semgrep backend",
	Run: func(cmd *cobra.Command, args []string) {
		if jsonLog {
			log.SetFormatter(&log.JSONFormatter{FieldMap: log.FieldMap{log.FieldKeyMsg: "event"}})
		}

		// setup signal handler for clean shutdown
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		doneCh := make(chan bool, 1)
		go func() {
			sig := <-sigCh
			log.WithField("signal", sig).Info("broker.shutdown")
			doneCh <- true
		}()

		// load config(s)
		config, err := pkg.LoadConfig(configFiles, deploymentId)
		if err != nil {
			log.Panic(err)
		}

		// start metrics
		if err := pkg.StartMetrics(config); err != nil {
			log.Panic(fmt.Errorf("failed to start metrics: %w", err))
		}

		// start the broker
		teardown, err := StartNetworkBroker(config)
		if err != nil {
			log.Panic(fmt.Errorf("failed to start broker: %v", err))
		}
		defer teardown()

		// wait for shutdown
		<-doneCh
	},
}

func StartNetworkBroker(config *pkg.Config) (func() error, error) {
	// bring up wireguard interface
	tnet, wireguardTeardown, err := config.Inbound.Wireguard.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start wireguard: %v", err)
	}

	// start periodic heartbeats
	heartbeatTeardown, err := config.Inbound.Heartbeat.Start(tnet, fmt.Sprintf("semgrep-network-broker/%v (rev %v)", build.Version, build.Revision))
	if err != nil {
		wireguardTeardown()
		return nil, fmt.Errorf("heartbeat failed: %v", err)
	}

	teardown := func() error {
		heartbeatTeardown()
		return wireguardTeardown()
	}

	// start inbound proxy (r2c --> customer)
	if err := config.Inbound.Start(tnet); err != nil {
		teardown()
		return nil, fmt.Errorf("failed to start inbound proxy: %v", err)
	}

	return teardown, nil
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringArrayVarP(&configFiles, "config", "c", nil, "config file(s)")
	rootCmd.PersistentFlags().BoolVarP(&jsonLog, "json-log", "j", false, "JSON log output")
	rootCmd.PersistentFlags().IntVarP(&deploymentId, "deployment-id", "d", 0, "Semgrep deployment ID")
}
