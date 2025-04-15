package config

import "os"

type Config struct {
	Listen string
	Secret string
	DbPath string
}

func NewConfig() Config {
	var cfg Config
	// скрытая реализация загрузки
	cfg.LoadEnv()
	return cfg
}

func GetOrDefault(key string, defaultValue string) string {
	value, ok := os.LookupEnv(key)
	if !ok {
		return defaultValue
	}
	return value
}

func (c *Config) LoadEnv() {
	c.Listen = GetOrDefault("SERVER_ADDRESS", ":8080")
	c.Secret = GetOrDefault("JWT_SECRET", "dev-secret")
	c.DbPath = GetOrDefault("DATABASE_URL", "")
}
