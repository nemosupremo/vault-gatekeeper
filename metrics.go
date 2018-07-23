package gatekeeper

import (
	"os"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/alexcesaro/statsd.v2"
)

type metrics struct {
	g      *Gatekeeper
	statsd struct {
		c *statsd.Client
	}
}

func (g *Gatekeeper) NewMetrics(conf Config) (*metrics, error) {
	m := &metrics{
		g: g,
	}
	reporter := false
	if conf.Metrics.Statsd.Host != "" {
		reporter = true
		options := []statsd.Option{
			statsd.Address(conf.Metrics.Statsd.Host),
			statsd.Prefix(conf.Metrics.Statsd.Prefix),
			statsd.ErrorHandler(func(err error) {
				log.Warnf("statsd: %v", err)
			}),
		}
		if conf.Metrics.Statsd.Influx || conf.Metrics.Statsd.Datadog {
			if hostname, err := os.Hostname(); err == nil {
				options = append(options, statsd.Tags("host", hostname))
			}
			if conf.Metrics.Statsd.Influx {
				options = append(options, statsd.TagsFormat(statsd.InfluxDB))
			} else if conf.Metrics.Statsd.Datadog {
				options = append(options, statsd.TagsFormat(statsd.Datadog))
			}
		}
		if c, err := statsd.New(options...); err == nil {
			m.statsd.c = c
		} else {
			return nil, err
		}
	}
	if reporter {
		go m.reporter()
	}
	return m, nil
}

func (m *metrics) Request() {
	atomic.AddInt32(&m.g.Stats.Requests, 1)
	if m.statsd.c != nil {
		m.statsd.c.Count("requests", 1)
	}
}

func (m *metrics) Success() {
	atomic.AddInt32(&m.g.Stats.Successful, 1)
	if m.statsd.c != nil {
		m.statsd.c.Count("success", 1)
	}
}

func (m *metrics) Denied() {
	atomic.AddInt32(&m.g.Stats.Denied, 1)
	if m.statsd.c != nil {
		m.statsd.c.Count("denied", 1)
	}
}

func (m *metrics) Failed() {
	atomic.AddInt32(&m.g.Stats.Failed, 1)
	if m.statsd.c != nil {
		m.statsd.c.Count("failed", 1)
	}
}

func (m *metrics) reporter() {
	ticker := time.NewTicker(m.g.config.Metrics.Ticker)
	for {
		<-ticker.C
		peers := m.g.Peers()
		m.statsd.c.Gauge("peers", len(peers))
		unsealedPeers := 0
		for _, peer := range peers {
			if peer.Unsealed {
				unsealedPeers += 1
			}
		}
		m.statsd.c.Gauge("unsealed_peers", unsealedPeers)
		if m.g.IsUnsealed() {
			m.statsd.c.Gauge("sealed", 0)
			m.statsd.c.Gauge("unsealed", 1)
			m.statsd.c.Gauge("in_service", 1)
		} else {
			m.statsd.c.Gauge("sealed", 1)
			m.statsd.c.Gauge("unsealed", 0)
			if unsealedPeers > 0 {
				m.statsd.c.Gauge("in_service", 1)
			} else {
				m.statsd.c.Gauge("in_service", 0)
			}
		}
	}
}
