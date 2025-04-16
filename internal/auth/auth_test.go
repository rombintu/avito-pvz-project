package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenerateAndValidateToken(t *testing.T) {
	secret := "test-secret"
	userID := "user-123"
	role := RoleEmployee

	token, err := GenerateToken(userID, role, secret)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, err := ValidateToken(token, secret)
	assert.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, role, claims.Role)
}

func TestGenerateTokenWithExpiry(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		role          Role
		secret        string
		expiry        time.Duration
		wantErr       bool
		expectedError string
	}{
		{
			name:    "Success - valid token with future expiry",
			userID:  "user123",
			role:    RoleEmployee,
			secret:  "test-secret",
			expiry:  time.Hour,
			wantErr: false,
		},
		{
			name:    "Success - valid token with past expiry",
			userID:  "user456",
			role:    RoleModerator,
			secret:  "test-secret",
			expiry:  -time.Hour,
			wantErr: false,
		},
		{
			name:          "Empty user ID",
			userID:        "",
			role:          RoleEmployee,
			secret:        "test-secret",
			expiry:        time.Hour,
			wantErr:       true,
			expectedError: "user ID cannot be empty",
		},
		{
			name:          "Empty secret",
			userID:        "user123",
			role:          RoleEmployee,
			secret:        "",
			expiry:        time.Hour,
			wantErr:       true,
			expectedError: "secret cannot be empty",
		},
		{
			name:    "Invalid role",
			userID:  "user123",
			role:    Role("invalid"),
			secret:  "test-secret",
			expiry:  time.Hour,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateTokenWithExpiry(tt.userID, tt.role, tt.secret, tt.expiry)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.expectedError != "" {
					assert.Contains(t, err.Error(), tt.expectedError)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, token)

			// Для не-истекших токенов проверяем claims
			if tt.expiry > 0 {
				claims, err := ValidateToken(token, tt.secret)
				assert.NoError(t, err)
				assert.Equal(t, tt.userID, claims.UserID)
				assert.Equal(t, tt.role, claims.Role)
			}
		})
	}
}
func TestTokenExpiry(t *testing.T) {
	secret := "test-secret"

	t.Run("Token should be valid before expiry", func(t *testing.T) {
		token, err := GenerateTokenWithExpiry("user123", RoleEmployee, secret, time.Hour)
		assert.NoError(t, err)

		claims, err := ValidateToken(token, secret)
		assert.NoError(t, err)
		assert.Equal(t, "user123", claims.UserID)
	})

	t.Run("Token should be invalid after expiry", func(t *testing.T) {
		token, err := GenerateTokenWithExpiry("user456", RoleModerator, secret, -time.Hour)
		assert.NoError(t, err)

		_, err = ValidateToken(token, secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})
}

func TestTokenSignature(t *testing.T) {
	t.Run("Valid signature", func(t *testing.T) {
		token, err := GenerateTokenWithExpiry("user123", RoleEmployee, "correct-secret", time.Hour)
		assert.NoError(t, err)

		_, err = ValidateToken(token, "correct-secret")
		assert.NoError(t, err)
	})

	t.Run("Invalid signature", func(t *testing.T) {
		token, err := GenerateTokenWithExpiry("user123", RoleEmployee, "correct-secret", time.Hour)
		assert.NoError(t, err)

		_, err = ValidateToken(token, "wrong-secret")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signature")
	})
}
