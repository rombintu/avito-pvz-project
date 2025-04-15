package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rombintu/avito-pvz-project/internal/auth"
	"github.com/rombintu/avito-pvz-project/internal/config"
	"github.com/rombintu/avito-pvz-project/internal/mocks"
	"github.com/rombintu/avito-pvz-project/internal/models"
	"github.com/rombintu/avito-pvz-project/internal/storage/drivers"
	"github.com/stretchr/testify/assert"
)

func setupTest(t *testing.T) (*Server, *mocks.MockStorage, string, string) {
	ctrl := gomock.NewController(t)
	mockStorage := mocks.NewMockStorage(ctrl)

	gin.SetMode(gin.TestMode)
	gin.DefaultWriter = io.Discard

	srv := NewServer(ServerOpts{
		Storage: mockStorage,
		Config: config.Config{
			Secret: "test-secret",
		},
	})

	srv.SetupRoutes()

	moderatorToken, err := auth.GenerateToken(uuid.NewString(), auth.RoleModerator, srv.config.Secret)
	assert.NoError(t, err)

	employeeToken, err := auth.GenerateToken(uuid.NewString(), auth.RoleEmployee, srv.config.Secret)
	assert.NoError(t, err)

	return srv, mockStorage, moderatorToken, employeeToken
}

func TestDummyLogin(t *testing.T) {
	srv, _, _, _ := setupTest(t)

	tests := []struct {
		name       string
		role       string
		wantStatus int
	}{
		{"Valid employee", "employee", http.StatusOK},
		{"Valid moderator", "moderator", http.StatusOK},
		{"Invalid role", "admin", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := map[string]string{"role": tt.role}
			jsonBody, _ := json.Marshal(body)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/dummyLogin", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")

			srv.router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
			if tt.wantStatus == http.StatusOK {
				var response map[string]string
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.NotEmpty(t, response["token"])
			}
		})
	}
}

func TestRegister(t *testing.T) {
	srv, mockStorage, _, _ := setupTest(t)

	tests := []struct {
		name         string
		body         map[string]interface{}
		mockSetup    func()
		wantStatus   int
		wantErrorMsg string
	}{
		{
			"Success",
			map[string]interface{}{
				"email":    "test@example.com",
				"password": "password123",
				"role":     "employee",
			},
			func() {
				mockStorage.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(nil)
			},
			http.StatusCreated,
			"",
		},
		{
			"Duplicate email",
			map[string]interface{}{
				"email":    "duplicate@example.com",
				"password": "password123",
				"role":     "moderator",
			},
			func() {
				mockStorage.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(drivers.ErrDuplicateEmail)
			},
			http.StatusConflict,
			"email already exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()

			jsonBody, _ := json.Marshal(tt.body)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")

			srv.router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
			if tt.wantErrorMsg != "" {
				var response map[string]string
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Contains(t, response["error"], tt.wantErrorMsg)
			}
		})
	}
}

func TestLogin(t *testing.T) {
	srv, mockStorage, _, _ := setupTest(t)

	testUser := &models.User{
		ID:       uuid.NewString(),
		Email:    "test@example.com",
		Password: "correct-password",
		Role:     "employee",
	}

	tests := []struct {
		name         string
		body         map[string]string
		mockSetup    func()
		wantStatus   int
		wantErrorMsg string
	}{
		{
			"Success",
			map[string]string{
				"email":    "test@example.com",
				"password": "correct-password",
			},
			func() {
				mockStorage.EXPECT().GetUserByEmail(gomock.Any(), "test@example.com").Return(testUser, nil)
			},
			http.StatusOK,
			"",
		},
		{
			"Wrong password",
			map[string]string{
				"email":    "test@example.com",
				"password": "wrong-password",
			},
			func() {
				mockStorage.EXPECT().GetUserByEmail(gomock.Any(), "test@example.com").Return(testUser, nil)
			},
			http.StatusUnauthorized,
			"invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()

			jsonBody, _ := json.Marshal(tt.body)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")

			srv.router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
			if tt.wantStatus == http.StatusOK {
				var response map[string]string
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.NotEmpty(t, response["token"])
			}
		})
	}
}

func TestCreatePVZ(t *testing.T) {
	srv, _, moderatorToken, employeeToken := setupTest(t)

	t.Run("Success - moderator", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockStorage := mocks.NewMockStorage(ctrl)
		srv.storage = mockStorage // Подменяем хранилище на новый мок

		pvz := models.PVZ{
			ID:               uuid.NewString(),
			RegistrationDate: time.Now(),
			City:             "Москва",
		}

		mockStorage.EXPECT().CreatePVZ(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, p *models.PVZ) error {
				assert.Equal(t, pvz.City, p.City)
				return nil
			},
		).Times(1) // Ожидаем ровно один вызов

		jsonBody, _ := json.Marshal(pvz)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/pvz", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+moderatorToken)

		srv.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("Forbidden - employee", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		// Не ожидаем вызовов к хранилищу для этого теста
		mockStorage := mocks.NewMockStorage(ctrl)
		srv.storage = mockStorage

		pvz := models.PVZ{
			ID:               uuid.NewString(),
			RegistrationDate: time.Now(),
			City:             "Москва",
		}

		jsonBody, _ := json.Marshal(pvz)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/pvz", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+employeeToken)

		srv.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestGetPVZs(t *testing.T) {
	srv, mockStorage, moderatorToken, employeeToken := setupTest(t)

	testPVZs := []*models.PVZ{
		{
			ID:               uuid.NewString(),
			RegistrationDate: time.Now(),
			City:             "Москва",
		},
	}

	t.Run("Success - moderator", func(t *testing.T) {
		mockStorage.EXPECT().GetPVZs(gomock.Any(), gomock.Any()).Return(testPVZs, nil)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/pvz", nil)
		req.Header.Set("Authorization", "Bearer "+moderatorToken)

		srv.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Success - employee", func(t *testing.T) {
		mockStorage.EXPECT().GetPVZs(gomock.Any(), gomock.Any()).Return(testPVZs, nil)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/pvz", nil)
		req.Header.Set("Authorization", "Bearer "+employeeToken)

		srv.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestCreateReception(t *testing.T) {
	srv, mockStorage, _, employeeToken := setupTest(t)

	t.Run("Success", func(t *testing.T) {
		pvzID := uuid.NewString()
		body := map[string]string{"pvzId": pvzID}

		mockStorage.EXPECT().CreateReception(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, r *models.Reception) error {
				assert.Equal(t, pvzID, r.PVZID)
				assert.Equal(t, "in_progress", r.Status)
				return nil
			},
		)

		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/receptions", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+employeeToken)

		srv.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})
}

func TestAddProduct(t *testing.T) {
	srv, mockStorage, _, employeeToken := setupTest(t)

	t.Run("Success", func(t *testing.T) {
		pvzID := uuid.NewString()
		receptionID := uuid.NewString()
		productType := "электроника"

		body := map[string]string{
			"type":  productType,
			"pvzId": pvzID,
		}

		mockStorage.EXPECT().GetOpenReception(gomock.Any(), pvzID).Return(&models.Reception{
			ID:       receptionID,
			PVZID:    pvzID,
			Status:   "in_progress",
			DateTime: time.Now(),
		}, nil)

		mockStorage.EXPECT().AddProduct(gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, p *models.Product) error {
				assert.Equal(t, productType, p.Type)
				assert.Equal(t, receptionID, p.ReceptionID)
				return nil
			},
		)

		jsonBody, _ := json.Marshal(body)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/products", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+employeeToken)

		srv.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})
}

func TestCloseLastReception(t *testing.T) {
	srv, mockStorage, _, employeeToken := setupTest(t)

	t.Run("Success", func(t *testing.T) {
		pvzID := uuid.NewString()
		receptionID := uuid.NewString()

		mockStorage.EXPECT().GetOpenReception(gomock.Any(), pvzID).Return(&models.Reception{
			ID:     receptionID,
			PVZID:  pvzID,
			Status: "in_progress",
		}, nil)

		mockStorage.EXPECT().CloseReception(gomock.Any(), receptionID).Return(nil)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/pvz/"+pvzID+"/close_last_reception", nil)
		req.Header.Set("Authorization", "Bearer "+employeeToken)

		srv.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestDeleteLastProduct(t *testing.T) {
	srv, mockStorage, _, employeeToken := setupTest(t)

	t.Run("Success", func(t *testing.T) {
		pvzID := uuid.NewString()
		receptionID := uuid.NewString()
		productID := uuid.NewString()

		mockStorage.EXPECT().GetOpenReception(gomock.Any(), pvzID).Return(&models.Reception{
			ID:     receptionID,
			PVZID:  pvzID,
			Status: "in_progress",
		}, nil)

		mockStorage.EXPECT().GetLastProduct(gomock.Any(), receptionID).Return(&models.Product{
			ID:          productID,
			ReceptionID: receptionID,
			Type:        "электроника",
			DateTime:    time.Now(),
		}, nil)

		mockStorage.EXPECT().DeleteProduct(gomock.Any(), productID).Return(nil)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/pvz/"+pvzID+"/delete_last_product", nil)
		req.Header.Set("Authorization", "Bearer "+employeeToken)

		srv.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
