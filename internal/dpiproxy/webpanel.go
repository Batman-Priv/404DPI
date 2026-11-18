package dpiproxy

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

var processStartTime = time.Now()

type activitySnapshot struct {
	UptimeSeconds int64                `json:"uptime_seconds"`
	Config        webPanelConfigView   `json:"config"`
	RecentQUIC    []webPanelQUICEntry  `json:"recent_quic_sni"`
	Domains       []webPanelDomainStat `json:"domains"`
}

type webPanelConfigView struct {
	FragmentMethod  string `json:"fragment_method"`
	Adaptive        bool   `json:"adaptive"`
	RaceStrategies  bool   `json:"race_strategies"`
	TLSProfile      string `json:"tls_profile"`
	TLSGrease       bool   `json:"tls_grease"`
	ECHGrease       bool   `json:"ech_grease"`
	QUICMode        string `json:"quic_mode"`
	BlacklistType   string `json:"blacklist_type"`
	FrontMapPairs   int    `json:"front_map_pairs"`
	DoHEnabled      bool   `json:"doh_enabled"`
	TransparentMode bool   `json:"transparent_mode"`
	LogDomainsPlain bool   `json:"log_domains_plain"`
}

type webPanelQUICEntry struct {
	When string `json:"when"`
	Host string `json:"host"`
	SNI  string `json:"sni"`
}

type webPanelDomainStat struct {
	Domain     string  `json:"domain"`
	Strategy   string  `json:"strategy"`
	Attempts   int64   `json:"attempts"`
	Successes  int64   `json:"successes"`
	Confidence float64 `json:"confidence"`
}

func startWebPanel(mux *http.ServeMux, config *Config, stats *Statistics, s *ProxyServer) {
	if mux == nil {
		return
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(webPanelHTML))
	})

	mux.HandleFunc("/activity", func(w http.ResponseWriter, r *http.Request) {
		snap := activitySnapshot{
			UptimeSeconds: int64(time.Since(processStartTime).Seconds()),
			Config: webPanelConfigView{
				FragmentMethod:  config.FragmentMethod,
				Adaptive:        config.Adaptive,
				RaceStrategies:  config.RaceStrategies,
				TLSProfile:      config.TLSProfile,
				TLSGrease:       config.TLSGrease,
				ECHGrease:       config.ECHGrease,
				QUICMode:        config.resolvedQUICMode(),
				BlacklistType:   s.getBlacklistType(),
				FrontMapPairs:   len(config.FrontMap),
				DoHEnabled:      config.EnableDoH,
				TransparentMode: config.EnableTransparent,
				LogDomainsPlain: config.LogDomains,
			},
		}

		for _, e := range recentQUICSNISnapshot() {
			snap.RecentQUIC = append(snap.RecentQUIC, webPanelQUICEntry{
				When: e.When.Format("15:04:05"),
				Host: e.Host,
				SNI:  e.SNI,
			})
		}

		s.stratCache.Range(func(k, v interface{}) bool {
			rec := v.(*StrategyRecord).snapshot()
			attempts := rec.Attempts
			if attempts == 0 {
				return true
			}
			snap.Domains = append(snap.Domains, webPanelDomainStat{
				Domain:     k.(string),
				Strategy:   rec.Strategy.Name,
				Attempts:   attempts,
				Successes:  rec.Successes,
				Confidence: confidenceOf(rec),
			})
			return true
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(snap)
	})
}

const webPanelHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DPI Bypass Proxy</title>
<style>
  :root {
    --bg: #0b0f14; --panel: #121821; --border: #1e2733; --text: #e6edf3;
    --muted: #7d8590; --accent: #4fa8ff; --good: #3fb950; --bad: #f85149; --warn: #d29922;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px; background: var(--bg); color: var(--text);
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  h1 { font-size: 18px; font-weight: 600; margin: 0 0 4px; }
  .sub { color: var(--muted); font-size: 12px; margin-bottom: 24px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
    padding: 14px 16px;
  }
  .card .n { font-size: 22px; font-weight: 600; }
  .card .l { color: var(--muted); font-size: 12px; margin-top: 2px; }
  section { margin-bottom: 24px; }
  section h2 {
    font-size: 13px; text-transform: uppercase; letter-spacing: 0.04em;
    color: var(--muted); margin: 0 0 10px; font-weight: 600;
  }
  table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); font-size: 13px; }
  th { color: var(--muted); font-weight: 500; font-size: 11px; text-transform: uppercase; }
  tr:last-child td { border-bottom: none; }
  .pill { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }
  .pill.on { background: rgba(63,185,80,0.15); color: var(--good); }
  .pill.off { background: rgba(125,133,144,0.15); color: var(--muted); }
  .empty { color: var(--muted); font-size: 13px; padding: 16px; text-align: center; }
  .conf-bar { display: inline-block; width: 60px; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; vertical-align: middle; margin-right: 6px; }
  .conf-bar > div { height: 100%; background: var(--accent); }
  code { background: var(--border); padding: 1px 5px; border-radius: 4px; font-size: 12px; }
</style>
</head>
<body>
  <h1>DPI Bypass Proxy</h1>
  <div class="sub" id="uptime">connecting...</div>

  <div class="grid" id="stat-cards"></div>

  <section>
    <h2>Configuration</h2>
    <table id="config-table"><tbody></tbody></table>
  </section>

  <section>
    <h2>Recent QUIC Initial SNI</h2>
    <table>
      <thead><tr><th>Time</th><th>SOCKS5 target</th><th>SNI</th></tr></thead>
      <tbody id="quic-rows"></tbody>
    </table>
  </section>

  <section>
    <h2>Per-domain strategy cache</h2>
    <table>
      <thead><tr><th>Domain</th><th>Strategy</th><th>Confidence</th><th>Attempts</th></tr></thead>
      <tbody id="domain-rows"></tbody>
    </table>
  </section>

<script>
function fmtUptime(s) {
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return h + "h " + m + "m " + sec + "s";
}
function pill(on) {
  return '<span class="pill ' + (on ? 'on">on' : 'off">off') + '</span>';
}
function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function refresh() {
  try {
    const [statsRes, activityRes] = await Promise.all([fetch('/stats'), fetch('/activity')]);
    const stats = await statsRes.json();
    const activity = await activityRes.json();

    document.getElementById('uptime').textContent =
      'up ' + fmtUptime(activity.uptime_seconds) + ' · privacy mode: ' +
      (activity.config.log_domains_plain ? 'plaintext domains (-log-domains)' : 'domains tokenized on disk/logs');

    document.getElementById('stat-cards').innerHTML = [
      ['Total', stats.total_connections],
      ['Bypassed', stats.bypassed],
      ['Direct', stats.direct],
      ['Errors', stats.errors],
      ['Downloaded', formatBytes(stats.traffic_in_bytes)],
      ['Uploaded', formatBytes(stats.traffic_out_bytes)],
    ].map(([label, val]) =>
      '<div class="card"><div class="n">' + esc(val) + '</div><div class="l">' + label + '</div></div>'
    ).join('');

    const c = activity.config;
    const rows = [
      ['Fragment method', '<code>' + esc(c.fragment_method) + '</code>'],
      ['Adaptive learning', pill(c.adaptive)],
      ['Strategy racing', pill(c.race_strategies)],
      ['TLS profile', c.tls_profile ? '<code>' + esc(c.tls_profile) + '</code>' : '<span class="l">none</span>'],
      ['TLS GREASE', pill(c.tls_grease)],
      ['ECH GREASE (RFC 9849, shape-only)', pill(c.ech_grease)],
      ['QUIC mode', '<code>' + esc(c.quic_mode) + '</code>'],
      ['Blacklist', '<code>' + esc(c.blacklist_type) + '</code>'],
      ['Domain fronting pairs', esc(c.front_map_pairs)],
      ['DNS-over-HTTPS', pill(c.doh_enabled)],
      ['Transparent (whole-system) mode', pill(c.transparent_mode)],
    ].map(([label, val]) => '<tr><td>' + label + '</td><td>' + val + '</td></tr>').join('');
    document.querySelector('#config-table tbody').innerHTML = rows;

    const quicRows = (activity.recent_quic_sni || []);
    document.getElementById('quic-rows').innerHTML = quicRows.length
      ? quicRows.map(e => '<tr><td>' + esc(e.when) + '</td><td>' + esc(e.host) + '</td><td>' + esc(e.sni) + '</td></tr>').join('')
      : '<tr><td colspan="3" class="empty">No QUIC Initial packets inspected yet (needs -quic-mode inspect)</td></tr>';

    const domainRows = (activity.domains || []).sort((a, b) => b.attempts - a.attempts);
    document.getElementById('domain-rows').innerHTML = domainRows.length
      ? domainRows.map(d =>
          '<tr><td>' + esc(d.domain) + '</td><td><code>' + esc(d.strategy) + '</code></td><td>' +
          '<span class="conf-bar"><div style="width:' + Math.round(d.confidence * 100) + '%"></div></span>' +
          Math.round(d.confidence * 100) + '%</td><td>' + d.attempts + '</td></tr>'
        ).join('')
      : '<tr><td colspan="4" class="empty">No adaptive strategy data yet (needs -adaptive)</td></tr>';
  } catch (e) {
    document.getElementById('uptime').textContent = 'disconnected - retrying...';
  }
}

function formatBytes(n) {
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + ' ' + units[i];
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
`

func confidenceOf(r strategyRecordJSON) float64 {
	if r.Attempts == 0 {
		return 0
	}
	return float64(r.Successes) / float64(r.Attempts)
}

func wireWebPanel(mux *http.ServeMux, config *Config, stats *Statistics, s *ProxyServer) {
	startWebPanel(mux, config, stats, s)
	if config.StatsHTTP {
		log.Printf("Web panel: http://127.0.0.1:%d/", config.StatsPort)
	}
}
