package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/proto"
)

func TestCreateProxy_NoPcap(t *testing.T) {
	// Setup configuration that dAppModeHTTP PCAP (root privileges)
	cfg := &config.Config{}

	// App Config
	cfg.Startup.App = config.AppOptions{
		Mode:       config.AppModeHTTP,
		ListenAddr: net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
	}

	// Conn Config
	cfg.Runtime.Conn = config.ConnOptions{
		DefaultFakeTTL: uint8(64),
		DNSTimeout:     time.Duration(0),
		TCPTimeout:     time.Duration(0),
		UDPIdleTimeout: time.Duration(0),
	}

	// HTTPS Config (Ensure FakeCount is 0 to disable PCAP)
	cfg.Runtime.HTTPS = config.HTTPSOptions{
		Disorder:   false,
		FakeCount:  uint8(0),
		FakePacket: proto.NewFakeTLSMessage([]byte{}),
		SplitMode:  config.HTTPSSplitModeChunk,
		ChunkSize:  uint8(10),
		Skip:       false,
	}

	// Rules
	cfg.Startup.Rules = nil

	// DNS Config
	cfg.Runtime.DNS = config.DNSOptions{
		Mode:     config.DNSModeUDP,
		Addr:     net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53},
		HTTPSURL: "https://dns.google/dns-query",
		QType:    config.DNSQueryIPv4,
		Cache:    false,
	}

	logger := zerolog.Nop()
	p, err := createServer(context.Background(), logger, cfg)
	require.NoError(t, err)
	assert.NotNil(t, p)
}

func TestCreateProxy_WithPolicy(t *testing.T) {
	cfg := &config.Config{}

	// App Config
	cfg.Startup.App = config.AppOptions{
		Mode:       config.AppModeHTTP,
		ListenAddr: net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
	}

	// Conn Config
	cfg.Runtime.Conn = config.ConnOptions{
		DefaultFakeTTL: uint8(64),
		DNSTimeout:     time.Duration(0),
		TCPTimeout:     time.Duration(0),
		UDPIdleTimeout: time.Duration(0),
	}

	// HTTPS Config
	cfg.Runtime.HTTPS = config.HTTPSOptions{
		FakeCount: uint8(0),
	}

	// One rule
	cfg.Startup.Rules = []config.Rule{
		{
			Name: "test-rule",
			Match: &config.MatchAttrs{
				Domains: []string{"example.com"},
			},
			Config: config.RuntimeConfig{
				DNS: config.DNSOptions{
					Mode: config.DNSModeSystem,
				},
				HTTPS: config.HTTPSOptions{
					Skip: true,
				},
			},
		},
	}

	// DNS Config
	cfg.Runtime.DNS = config.DNSOptions{
		Mode:     config.DNSModeUDP,
		Addr:     net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53},
		HTTPSURL: "https://dns.google/dns-query",
		QType:    config.DNSQueryIPv4,
		Cache:    false,
	}

	logger := zerolog.Nop()
	p, err := createServer(context.Background(), logger, cfg)
	require.NoError(t, err)
	assert.NotNil(t, p)
}
