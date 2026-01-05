package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

type Target struct {
	URL      string            `json:"url"`
	Method   string            `json:"method"`
	Headers  map[string]string `json:"headers"`
	BodyFile string            `json:"body_file"`
}

type LoadConfig struct {
	Rate             int    `json:"rate"`
	Duration         string `json:"duration"`
	Concurrency      int    `json:"concurrency"`
	Timeout          string `json:"timeout"`
	DisableKeepAlive bool   `json:"disable_keepalive"`
	InsecureTLS      bool   `json:"insecure_tls"`
	HTTP2            bool   `json:"http2"`
}

type Output struct {
	JSONLPath string `json:"jsonl_path"`
}

type Config struct {
	Target Target     `json:"target"`
	Load   LoadConfig `json:"load"`
	Output Output     `json:"output"`
}

func ReadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

func WriteDefaultConfig(path string) error {
	def := DefaultConfig()
	data, err := json.MarshalIndent(def, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal default config: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// DefaultConfig
func DefaultConfig() Config {
	return Config{
		Target: Target{
			URL:    "https://example.com",
			Method: "GET",
			Headers: map[string]string{
				"User-Agent": "shard/1.0",
			},
			BodyFile: "",
		},
		Load: LoadConfig{
			Rate:             50,
			Duration:         "10s",
			Concurrency:      256,
			Timeout:          "10s",
			DisableKeepAlive: false,
			InsecureTLS:      false,
			HTTP2:            true,
		},
		Output: Output{
			JSONLPath: "results.jsonl",
		},
	}
}

// Validation
func (c *Config) Validate() error {
	if c.Target.URL == "" {
		return errors.New("target.url is required")
	}
	if c.Load.Rate <= 0 {
		return errors.New("load.rate must be > 0")
	}
	if c.Load.Concurrency <= 0 {
		return errors.New("load.concurrency must be > 0")
	}
	if _, err := time.ParseDuration(c.Load.Duration); err != nil {
		return fmt.Errorf("invalid load.duration: %v", err)
	}
	if _, err := time.ParseDuration(c.Load.Timeout); err != nil {
		return fmt.Errorf("invalid load.timeout: %v", err)
	}
	return nil
}
