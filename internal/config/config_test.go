package config

import (
	"os"
	"testing"

	"gotest.tools/assert"
)

func TestNewConfig(t *testing.T) {
	t.Run("Default values", func(t *testing.T) {
		// Очищаем env для теста
		os.Clearenv()

		cfg := NewConfig()

		assert.Equal(t, ":8080", cfg.Listen)
		assert.Equal(t, "dev-secret", cfg.Secret)
		assert.Equal(t, "", cfg.DbPath)
	})

	t.Run("Custom values from env", func(t *testing.T) {
		os.Clearenv()
		os.Setenv("SERVER_ADDRESS", ":9090")
		os.Setenv("JWT_SECRET", "test-secret")
		os.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/db")

		cfg := NewConfig()

		assert.Equal(t, ":9090", cfg.Listen)
		assert.Equal(t, "test-secret", cfg.Secret)
		assert.Equal(t, "postgres://user:pass@localhost:5432/db", cfg.DbPath)
	})
}

func TestGetOrDefault(t *testing.T) {
	tests := []struct {
		name         string
		envKey       string
		envValue     string
		defaultValue string
		expected     string
	}{
		{
			name:         "Env variable set",
			envKey:       "TEST_KEY",
			envValue:     "test-value",
			defaultValue: "default",
			expected:     "test-value",
		},
		{
			name:         "Env variable not set",
			envKey:       "NON_EXISTENT_KEY",
			envValue:     "",
			defaultValue: "default",
			expected:     "default",
		},
		{
			name:         "Empty env variable",
			envKey:       "EMPTY_KEY",
			envValue:     "",
			defaultValue: "default",
			expected:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Clearenv()
			if tt.envValue != "" || tt.envKey == "EMPTY_KEY" {
				os.Setenv(tt.envKey, tt.envValue)
			}

			result := GetOrDefault(tt.envKey, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLoadEnv(t *testing.T) {
	t.Run("Load with defaults", func(t *testing.T) {
		os.Clearenv()

		var cfg Config
		cfg.LoadEnv()

		assert.Equal(t, ":8080", cfg.Listen)
		assert.Equal(t, "dev-secret", cfg.Secret)
		assert.Equal(t, "", cfg.DbPath)
	})

	t.Run("Load with custom env", func(t *testing.T) {
		os.Clearenv()
		os.Setenv("SERVER_ADDRESS", ":9090")
		os.Setenv("JWT_SECRET", "custom-secret")
		os.Setenv("DATABASE_URL", "custom-db-url")

		var cfg Config
		cfg.LoadEnv()

		assert.Equal(t, ":9090", cfg.Listen)
		assert.Equal(t, "custom-secret", cfg.Secret)
		assert.Equal(t, "custom-db-url", cfg.DbPath)
	})

	t.Run("Partial env settings", func(t *testing.T) {
		os.Clearenv()
		os.Setenv("JWT_SECRET", "partial-secret")

		var cfg Config
		cfg.LoadEnv()

		assert.Equal(t, ":8080", cfg.Listen) // default
		assert.Equal(t, "partial-secret", cfg.Secret)
		assert.Equal(t, "", cfg.DbPath) // default
	})
}

func TestConfig_Integration(t *testing.T) {
	t.Run("NewConfig uses LoadEnv", func(t *testing.T) {
		os.Clearenv()
		os.Setenv("SERVER_ADDRESS", ":7070")

		cfg := NewConfig()

		assert.Equal(t, ":7070", cfg.Listen)
		assert.Equal(t, "dev-secret", cfg.Secret) // default
	})
}
