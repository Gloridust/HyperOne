// Package config loads HyperOne server and client settings from JSON files.
package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// Server is the on-disk server configuration.
type Server struct {
	Listen     string `json:"listen"`      // e.g. "0.0.0.0:443"
	Camouflage string `json:"camouflage"`  // real TLS site, e.g. "www.example.com:443"
	PSKHex     string `json:"psk_hex"`     // 32-byte PSK, hex-encoded
}

// Client is the on-disk client configuration.
type Client struct {
	Listen string `json:"listen"` // local SOCKS5 listen addr, e.g. "127.0.0.1:1080"
	Server string `json:"server"` // HyperOne server addr, e.g. "203.0.113.5:443"
	SNI    string `json:"sni"`    // camouflage domain, must match server's backend cert
	PSKHex string `json:"psk_hex"`
}

// LoadServer reads and validates a server config file.
func LoadServer(path string) (*Server, []byte, error) {
	var c Server
	if err := load(path, &c); err != nil {
		return nil, nil, err
	}
	if c.Listen == "" || c.Camouflage == "" {
		return nil, nil, fmt.Errorf("config: listen and camouflage are required")
	}
	psk, err := decodePSK(c.PSKHex)
	if err != nil {
		return nil, nil, err
	}
	return &c, psk, nil
}

// LoadClient reads and validates a client config file.
func LoadClient(path string) (*Client, []byte, error) {
	var c Client
	if err := load(path, &c); err != nil {
		return nil, nil, err
	}
	if c.Listen == "" || c.Server == "" || c.SNI == "" {
		return nil, nil, fmt.Errorf("config: listen, server and sni are required")
	}
	psk, err := decodePSK(c.PSKHex)
	if err != nil {
		return nil, nil, err
	}
	return &c, psk, nil
}

func load(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("config: parsing %s: %w", path, err)
	}
	return nil
}

func decodePSK(s string) ([]byte, error) {
	psk, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("config: psk_hex is not valid hex: %w", err)
	}
	if len(psk) < 16 {
		return nil, fmt.Errorf("config: psk must be at least 16 bytes (got %d)", len(psk))
	}
	return psk, nil
}
