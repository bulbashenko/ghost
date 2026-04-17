// Package config loads and validates GHOST server and client YAML configs.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ServerConfig is the YAML config for ghost-server.
type ServerConfig struct {
	// Listen address for TLS (e.g. ":443").
	Listen string `yaml:"listen"`

	// TLS certificate and key paths (Let's Encrypt).
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`

	// Server's Noise IK static keypair (base64).
	PrivateKey string `yaml:"private_key"`

	// Allowed client public keys (base64). Empty = accept any authenticated client.
	AllowedClients []string `yaml:"allowed_clients"`

	// FallbackTarget is the URL to reverse-proxy for unauthenticated requests
	// (e.g. "https://example.com").
	FallbackTarget string `yaml:"fallback_target"`

	// TUN interface configuration.
	TUN TUNConfig `yaml:"tun"`
}

// ClientConfig is the YAML config for ghost-client.
type ClientConfig struct {
	// Server address (host:port).
	ServerAddr string `yaml:"server_addr"`

	// SNI for TLS (defaults to host part of ServerAddr).
	SNI string `yaml:"sni"`

	// Client's Noise IK static keypair (base64).
	PrivateKey string `yaml:"private_key"`

	// Server's static public key (base64).
	ServerPublicKey string `yaml:"server_public_key"`

	// Browser fingerprint: "chrome", "firefox", "safari", "random".
	Fingerprint string `yaml:"fingerprint"`

	// TUN interface configuration.
	TUN TUNConfig `yaml:"tun"`
}

// TUNConfig configures the tunnel network interface.
type TUNConfig struct {
	// Name of the TUN device (default "ghost0").
	Name string `yaml:"name"`

	// Address is the local IP + CIDR (e.g. "10.7.0.2/24").
	Address string `yaml:"address"`

	// MTU of the TUN device (default 1400 to leave room for encapsulation).
	MTU int `yaml:"mtu"`

	// DNS server addresses (optional).
	DNS []string `yaml:"dns"`
}

func (t *TUNConfig) applyDefaults() {
	if t.Name == "" {
		t.Name = "ghost0"
	}
	if t.MTU == 0 {
		t.MTU = 1400
	}
}

// LoadServer reads and parses a server YAML config file.
func LoadServer(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	cfg.TUN.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadClient reads and parses a client YAML config file.
func LoadClient(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var cfg ClientConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	cfg.TUN.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *ServerConfig) validate() error {
	if c.Listen == "" {
		return fmt.Errorf("config: server.listen is required")
	}
	if c.PrivateKey == "" {
		return fmt.Errorf("config: server.private_key is required")
	}
	if c.FallbackTarget == "" {
		return fmt.Errorf("config: server.fallback_target is required")
	}
	if c.TUN.Address == "" {
		return fmt.Errorf("config: server.tun.address is required")
	}
	return nil
}

func (c *ClientConfig) validate() error {
	if c.ServerAddr == "" {
		return fmt.Errorf("config: client.server_addr is required")
	}
	if c.PrivateKey == "" {
		return fmt.Errorf("config: client.private_key is required")
	}
	if c.ServerPublicKey == "" {
		return fmt.Errorf("config: client.server_public_key is required")
	}
	if c.TUN.Address == "" {
		return fmt.Errorf("config: client.tun.address is required")
	}
	return nil
}
