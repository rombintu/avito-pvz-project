package auth

import (
	"testing"

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
