package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rombintu/avito-pvz-project/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestAuthMiddleware_Integration(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	secret := "test-secret"
	middlewareFunc := AuthMiddleware(secret)

	tests := []struct {
		name           string
		setupRequest   func() *http.Request
		expectedStatus int
		expectedError  string
	}{
		{
			name: "Success - valid token",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				token, _ := auth.GenerateToken("user123", auth.RoleEmployee, secret)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Expired token",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				// Генерируем токен с истекшим сроком
				token, _ := auth.GenerateTokenWithExpiry("user123", auth.RoleEmployee, secret, -time.Hour)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "Invalid token",
		},
		{
			name: "No Authorization header",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				return req
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "Authorization header is required",
		},
		{
			name: "Invalid token format",
			setupRequest: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				req.Header.Set("Authorization", "InvalidTokenFormat")
				return req
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "Bearer token not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/", middlewareFunc, func(c *gin.Context) {
				if tt.expectedStatus == http.StatusOK {
					_, exists := c.Get("claims")
					assert.True(t, exists)
				}
				c.Status(http.StatusOK)
			})

			req := tt.setupRequest()
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var response map[string]string
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedError, response["error"])
			}
		})
	}
}
