package main

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type config struct {
	Issuer               string         `yaml:"issuer"`
	TokenLifetimeSeconds int            `yaml:"token_lifetime_seconds"`
	Clients              []clientConfig `yaml:"clients"`
}

type clientConfig struct {
	ID     string         `yaml:"id"`
	Secret string         `yaml:"secret"`
	Scopes []string       `yaml:"scopes"`
	Claims map[string]any `yaml:"claims"`
}

func loadConfig(path string) (config, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return config{}, fmt.Errorf("read client config: %w", err)
	}

	var configuration config
	if err := yaml.Unmarshal(payload, &configuration); err != nil {
		return config{}, fmt.Errorf("decode client config: %w", err)
	}
	if configuration.Issuer == "" {
		return config{}, errors.New("client config must define issuer")
	}
	if configuration.TokenLifetimeSeconds <= 0 {
		return config{}, errors.New("client config must define a positive token_lifetime_seconds")
	}
	for index, client := range configuration.Clients {
		if client.ID == "" || client.Secret == "" {
			return config{}, fmt.Errorf("client at index %d must define id and secret", index)
		}
	}
	return configuration, nil
}
