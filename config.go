package main

import (
	"os"
	"time"

	"github.com/Azure/eraser/api/unversioned"
	"github.com/quay/claircore"
	"gopkg.in/yaml.v2"
)

type Config struct {
	CacheDir           string        `json:"cacheDir,omitempty"`
	Timeout            TimeoutConfig `json:"timeout,omitempty"`
	DeleteFailedImages bool          `json:"deleteFailedImages,omitempty"`
	Vulnerabilities    VulnConfig    `json:"vulnerabilities,omitempty"`
}

type VulnConfig struct {
	IgnoreUnfixed bool     `json:"ignoreUnfixed,omitempty"`
	Severities    []string `json:"severities,omitempty"`
}

func parseConfig(path string) (*Config, error) {
	cfg := defaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}

	var eraserConfig unversioned.EraserConfig
	err = yaml.Unmarshal(b, &eraserConfig)
	if err != nil {
		return cfg, err
	}

	scanCfgYaml := eraserConfig.Components.Scanner.Config
	scanCfgBytes := []byte("")
	if scanCfgYaml != nil {
		scanCfgBytes = []byte(*scanCfgYaml)
	}

	err = yaml.Unmarshal(scanCfgBytes, &cfg)
	if err != nil {
		return cfg, err
	}

	return cfg, nil
}

func defaultConfig() *Config {
	return &Config{
		CacheDir:           "/var/lib/clair",
		DeleteFailedImages: true,
		Vulnerabilities: VulnConfig{
			IgnoreUnfixed: true,
			Severities:    []string{claircore.Critical.String(), claircore.High.String(), claircore.Medium.String(), claircore.Low.String()},
		},
		Timeout: TimeoutConfig{
			Total:    unversioned.Duration(time.Hour * 23),
			PerImage: unversioned.Duration(time.Hour),
		},
	}
}
