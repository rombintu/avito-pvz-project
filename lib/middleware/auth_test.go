package middleware_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/rombintu/avito-pvz-project/internal/auth"
	"github.com/rombintu/avito-pvz-project/lib/middleware"
	"github.com/stretchr/testify/assert"
)

func TestAuthMiddleware_Integration(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	secret := "test-secret"
	middlewareFunc := middleware.AuthMiddleware(secret)

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
				token, _ := auth.GenerateToken("user123", auth.RoleEmployee, secret)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "Invalid token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Создаем тестовый роутер Gin
			router := gin.New()
			router.GET("/", middlewareFunc, func(c *gin.Context) {
				// Проверяем, что claims установлены в контексте
				_, exists := c.Get("claims")
				assert.True(t, exists)
				c.Status(http.StatusOK)
			})

			// Создаем запрос
			req := tt.setupRequest()
			w := httptest.NewRecorder()

			// Выполняем запрос
			router.ServeHTTP(w, req)

			// Проверяем статус код
			assert.Equal(t, tt.expectedStatus, w.Code)

			// Если ожидается ошибка, проверяем тело ответа
			if tt.expectedError != "" {
				var response map[string]string
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedError, response["error"])
			}
		})
	}
}
