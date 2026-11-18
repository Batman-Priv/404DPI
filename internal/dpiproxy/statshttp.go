package dpiproxy

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type statsSnapshot struct {
	Total    uint64 `json:"total_connections"`
	Bypassed uint64 `json:"bypassed"`
	Direct   uint64 `json:"direct"`
	Allowed  uint64 `json:"allowed"`
	Blocked  uint64 `json:"blocked"`
	Errors   uint64 `json:"errors"`
	InBytes  uint64 `json:"traffic_in_bytes"`
	OutByte  uint64 `json:"traffic_out_bytes"`

	FragmentMethod string `json:"fragment_method"`
	Adaptive       bool   `json:"adaptive"`
	BlacklistType  string `json:"blacklist_type"`
}

func startStatsHTTP(config *Config, stats *Statistics, s *ProxyServer) {
	if !config.StatsHTTP {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		snap := statsSnapshot{
			Total:          stats.totalConns.Load(),
			Bypassed:       stats.bypassedConns.Load(),
			Direct:         stats.directConns.Load(),
			Allowed:        stats.directConns.Load(),
			Blocked:        stats.bypassedConns.Load(),
			Errors:         stats.errorConns.Load(),
			InBytes:        stats.trafficIn.Load(),
			OutByte:        stats.trafficOut.Load(),
			FragmentMethod: config.FragmentMethod,
			Adaptive:       config.Adaptive,
			BlacklistType:  s.getBlacklistType(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(snap)
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# HELP dpi_connections_total Total connections accepted\n# TYPE dpi_connections_total counter\ndpi_connections_total %d\n", stats.totalConns.Load())
		fmt.Fprintf(w, "# HELP dpi_connections_bypassed Connections that got DPI-bypass handling\n# TYPE dpi_connections_bypassed counter\ndpi_connections_bypassed %d\n", stats.bypassedConns.Load())
		fmt.Fprintf(w, "# HELP dpi_connections_direct Connections passed straight through\n# TYPE dpi_connections_direct counter\ndpi_connections_direct %d\n", stats.directConns.Load())
		fmt.Fprintf(w, "# HELP dpi_connections_error Connections that errored out\n# TYPE dpi_connections_error counter\ndpi_connections_error %d\n", stats.errorConns.Load())
		fmt.Fprintf(w, "# HELP dpi_connections_active Currently open connections\n# TYPE dpi_connections_active gauge\ndpi_connections_active %d\n", stats.activeConns.Load())
		fmt.Fprintf(w, "# HELP dpi_bytes_in_total Bytes downloaded from remote servers\n# TYPE dpi_bytes_in_total counter\ndpi_bytes_in_total %d\n", stats.trafficIn.Load())
		fmt.Fprintf(w, "# HELP dpi_bytes_out_total Bytes uploaded to remote servers\n# TYPE dpi_bytes_out_total counter\ndpi_bytes_out_total %d\n", stats.trafficOut.Load())

		fmt.Fprintln(w, "# HELP dpi_strategy_attempts_total Fragmentation strategy attempts per domain\n# TYPE dpi_strategy_attempts_total counter")
		fmt.Fprintln(w, "# HELP dpi_strategy_successes_total Fragmentation strategy successes per domain\n# TYPE dpi_strategy_successes_total counter")
		s.stratCache.Range(func(k, v interface{}) bool {
			rec := v.(*StrategyRecord).snapshot()
			domain := k.(string)
			fmt.Fprintf(w, "dpi_strategy_attempts_total{domain=%q,strategy=%q} %d\n", domain, rec.Strategy.Name, rec.Attempts)
			fmt.Fprintf(w, "dpi_strategy_successes_total{domain=%q,strategy=%q} %d\n", domain, rec.Strategy.Name, rec.Successes)
			return true
		})
	})

	addr := fmt.Sprintf("127.0.0.1:%d", config.StatsPort)
	wireWebPanel(mux, config, stats, s)
	go func() {
		log.Printf("Local stats page on http://%s/stats (JSON) and http://%s/metrics (Prometheus)", addr, addr)
		srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("[WARN] stats HTTP server stopped: %v", err)
		}
	}()
}
