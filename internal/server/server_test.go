package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rombintu/avito-pvz-project/internal/auth"
	"github.com/rombintu/avito-pvz-project/internal/config"
	"github.com/rombintu/avito-pvz-project/internal/mocks"
	"github.com/rombintu/avito-pvz-project/internal/models"
	pvz_v1 "github.com/rombintu/avito-pvz-project/internal/proto"
	"github.com/rombintu/avito-pvz-project/internal/storage"
	"github.com/rombintu/avito-pvz-project/internal/storage/drivers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
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
		{"Empty role", "", http.StatusBadRequest},
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
			} else {
				var response map[string]string
				json.Unmarshal(w.Body.Bytes(), &response)
				assert.NotEmpty(t, response["error"])
			}
		})
	}
}

func TestRegister(t *testing.T) {
	srv, _, _, _ := setupTest(t)

	tests := []struct {
		name         string
		body         map[string]interface{}
		mockSetup    func(*mocks.MockStorage)
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
			func(m *mocks.MockStorage) {
				m.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(nil)
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
			func(m *mocks.MockStorage) {
				m.EXPECT().CreateUser(gomock.Any(), gomock.Any()).Return(drivers.ErrDuplicateEmail)
			},
			http.StatusConflict,
			"email already exists",
		},
		{
			"Invalid role",
			map[string]interface{}{
				"email":    "test@example.com",
				"password": "password123",
				"role":     "invalid",
			},
			func(m *mocks.MockStorage) {},
			http.StatusBadRequest,
			"Field validation for 'Role' failed on the 'oneof' tag",
		},
		{
			"Missing email",
			map[string]interface{}{
				"password": "password123",
				"role":     "employee",
			},
			func(m *mocks.MockStorage) {},
			http.StatusBadRequest,
			"Field validation for 'Email' failed on the 'required' tag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStorage := mocks.NewMockStorage(ctrl)
			tt.mockSetup(mockStorage)
			srv.storage = mockStorage

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
	srv, _, _, _ := setupTest(t)

	testUser := &models.User{
		ID:       uuid.NewString(),
		Email:    "test@example.com",
		Password: "correct-password",
		Role:     "employee",
	}

	tests := []struct {
		name         string
		body         map[string]string
		mockSetup    func(*mocks.MockStorage)
		wantStatus   int
		wantErrorMsg string
	}{
		{
			"Success",
			map[string]string{
				"email":    "test@example.com",
				"password": "correct-password",
			},
			func(m *mocks.MockStorage) {
				m.EXPECT().GetUserByEmail(gomock.Any(), "test@example.com").Return(testUser, nil)
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
			func(m *mocks.MockStorage) {
				m.EXPECT().GetUserByEmail(gomock.Any(), "test@example.com").Return(testUser, nil)
			},
			http.StatusUnauthorized,
			"invalid credentials",
		},
		{
			"User not found",
			map[string]string{
				"email":    "notfound@example.com",
				"password": "password",
			},
			func(m *mocks.MockStorage) {
				m.EXPECT().GetUserByEmail(gomock.Any(), "notfound@example.com").Return(nil, drivers.ErrNotFound)
			},
			http.StatusUnauthorized,
			"invalid credentials",
		},
		{
			"Missing email",
			map[string]string{
				"password": "password",
			},
			func(m *mocks.MockStorage) {},
			http.StatusBadRequest,
			"Field validation for 'Email' failed on the 'required' tag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStorage := mocks.NewMockStorage(ctrl)
			tt.mockSetup(mockStorage)
			srv.storage = mockStorage

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
			} else if tt.wantErrorMsg != "" {
				var response map[string]string
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Contains(t, response["error"], tt.wantErrorMsg)
			}
		})
	}
}

func TestCreatePVZ(t *testing.T) {
	srv, _, moderatorToken, employeeToken := setupTest(t)

	tests := []struct {
		name         string
		token        string
		body         interface{}
		mockSetup    func(*mocks.MockStorage)
		wantStatus   int
		wantErrorMsg string
	}{
		{
			"Success - moderator",
			moderatorToken,
			models.PVZ{
				City: "Москва",
			},
			func(m *mocks.MockStorage) {
				m.EXPECT().CreatePVZ(gomock.Any(), gomock.Any()).Return(nil)
			},
			http.StatusCreated,
			"",
		},
		{
			"Forbidden - employee",
			employeeToken,
			models.PVZ{
				City: "Москва",
			},
			func(m *mocks.MockStorage) {},
			http.StatusForbidden,
			"access denied",
		},
		{
			"Invalid token",
			"invalid-token",
			models.PVZ{
				City: "Москва",
			},
			func(m *mocks.MockStorage) {},
			http.StatusUnauthorized,
			"Invalid token", // Exact match
		},
		{
			"Missing city",
			moderatorToken,
			map[string]interface{}{
				"wrong_field": "Москва",
			},
			func(m *mocks.MockStorage) {},
			http.StatusBadRequest,
			"invalid city", // Exact match
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStorage := mocks.NewMockStorage(ctrl)
			tt.mockSetup(mockStorage)
			srv.storage = mockStorage

			jsonBody, _ := json.Marshal(tt.body)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/pvz", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tt.token)

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

func TestGetPVZs(t *testing.T) {
	srv, _, moderatorToken, employeeToken := setupTest(t)

	testPVZs := []*models.PVZ{
		{
			ID:               uuid.NewString(),
			RegistrationDate: time.Now(),
			City:             "Москва",
		},
		{
			ID:               uuid.NewString(),
			RegistrationDate: time.Now().Add(-24 * time.Hour),
			City:             "Санкт-Петербург",
		},
	}

	tests := []struct {
		name       string
		token      string
		mockSetup  func(*mocks.MockStorage)
		wantStatus int
		wantCount  int
	}{
		{
			"Success - moderator",
			moderatorToken,
			func(m *mocks.MockStorage) {
				m.EXPECT().GetPVZs(gomock.Any(), gomock.Any()).Return(testPVZs, nil)
			},
			http.StatusOK,
			2,
		},
		{
			"Success - employee",
			employeeToken,
			func(m *mocks.MockStorage) {
				m.EXPECT().GetPVZs(gomock.Any(), gomock.Any()).Return(testPVZs, nil)
			},
			http.StatusOK,
			2,
		},
		{
			"Empty result",
			moderatorToken,
			func(m *mocks.MockStorage) {
				m.EXPECT().GetPVZs(gomock.Any(), gomock.Any()).Return([]*models.PVZ{}, nil)
			},
			http.StatusOK,
			0,
		},
		{
			"Database error",
			moderatorToken,
			func(m *mocks.MockStorage) {
				m.EXPECT().GetPVZs(gomock.Any(), gomock.Any()).Return(nil, assert.AnError)
			},
			http.StatusInternalServerError,
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStorage := mocks.NewMockStorage(ctrl)
			tt.mockSetup(mockStorage)
			srv.storage = mockStorage

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/pvz", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)

			srv.router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
			if tt.wantStatus == http.StatusOK {
				var response []models.PVZ
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, tt.wantCount, len(response))
			}
		})
	}
}

func TestCreateReception(t *testing.T) {
	srv, _, _, employeeToken := setupTest(t)

	tests := []struct {
		name         string
		token        string
		body         map[string]string
		mockSetup    func(*mocks.MockStorage)
		wantStatus   int
		wantErrorMsg string
	}{
		{
			"Success",
			employeeToken,
			map[string]string{"pvzId": uuid.NewString()},
			func(m *mocks.MockStorage) {
				m.EXPECT().CreateReception(gomock.Any(), gomock.Any()).Return(nil)
			},
			http.StatusCreated,
			"",
		},
		{
			"Missing pvzId",
			employeeToken,
			map[string]string{},
			func(m *mocks.MockStorage) {},
			http.StatusBadRequest,
			"Field validation for 'PVZID' failed on the 'required' tag",
		},
		{
			"Invalid pvzId",
			employeeToken,
			map[string]string{"pvzId": "invalid"},
			func(m *mocks.MockStorage) {},
			http.StatusBadRequest,
			"Field validation for 'PVZID' failed on the 'uuid' tag",
		},
		{
			"Database error",
			employeeToken,
			map[string]string{"pvzId": uuid.NewString()},
			func(m *mocks.MockStorage) {
				m.EXPECT().CreateReception(gomock.Any(), gomock.Any()).Return(assert.AnError)
			},
			http.StatusInternalServerError,
			"failed to create reception",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStorage := mocks.NewMockStorage(ctrl)
			tt.mockSetup(mockStorage)
			srv.storage = mockStorage

			jsonBody, _ := json.Marshal(tt.body)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/receptions", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tt.token)

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

func TestAddProduct(t *testing.T) {
	srv, _, _, employeeToken := setupTest(t)

	validPVZID := uuid.NewString()
	validReception := &models.Reception{
		ID:       uuid.NewString(),
		PVZID:    validPVZID,
		Status:   "in_progress",
		DateTime: time.Now(),
	}

	tests := []struct {
		name         string
		token        string
		body         map[string]string
		mockSetup    func(*mocks.MockStorage)
		wantStatus   int
		wantErrorMsg string
	}{
		{
			"Success",
			employeeToken,
			map[string]string{
				"type":  "электроника",
				"pvzId": validPVZID,
			},
			func(m *mocks.MockStorage) {
				m.EXPECT().GetOpenReception(gomock.Any(), validPVZID).Return(validReception, nil)
				m.EXPECT().AddProduct(gomock.Any(), gomock.Any()).Return(nil)
			},
			http.StatusCreated,
			"",
		},
		{
			"No open reception",
			employeeToken,
			map[string]string{
				"type":  "электроника",
				"pvzId": validPVZID,
			},
			func(m *mocks.MockStorage) {
				m.EXPECT().GetOpenReception(gomock.Any(), validPVZID).Return(nil, drivers.ErrNotFound)
			},
			http.StatusBadRequest,
			"no open reception",
		},
		{
			"Missing type",
			employeeToken,
			map[string]string{
				"pvzId": validPVZID,
			},
			func(m *mocks.MockStorage) {},
			http.StatusBadRequest,
			"Field validation for 'Type' failed on the 'required' tag",
		},
		{
			"Database error",
			employeeToken,
			map[string]string{
				"type":  "электроника",
				"pvzId": validPVZID,
			},
			func(m *mocks.MockStorage) {
				m.EXPECT().GetOpenReception(gomock.Any(), validPVZID).Return(validReception, nil)
				m.EXPECT().AddProduct(gomock.Any(), gomock.Any()).Return(assert.AnError)
			},
			http.StatusInternalServerError,
			"failed to add product",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStorage := mocks.NewMockStorage(ctrl)
			tt.mockSetup(mockStorage)
			srv.storage = mockStorage

			jsonBody, _ := json.Marshal(tt.body)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/products", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tt.token)

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

func TestCloseLastReception(t *testing.T) {
	srv, _, _, employeeToken := setupTest(t)

	validPVZID := uuid.NewString()
	validReception := &models.Reception{
		ID:     uuid.NewString(),
		PVZID:  validPVZID,
		Status: "in_progress",
	}

	tests := []struct {
		name         string
		pvzID        string
		mockSetup    func(*mocks.MockStorage)
		wantStatus   int
		wantErrorMsg string
	}{
		{
			"Success",
			validPVZID,
			func(m *mocks.MockStorage) {
				m.EXPECT().GetOpenReception(gomock.Any(), validPVZID).Return(validReception, nil)
				m.EXPECT().CloseReception(gomock.Any(), validReception.ID).Return(nil)
			},
			http.StatusOK,
			"",
		},
		{
			"No open reception",
			validPVZID,
			func(m *mocks.MockStorage) {
				m.EXPECT().GetOpenReception(gomock.Any(), validPVZID).Return(nil, drivers.ErrNotFound)
			},
			http.StatusBadRequest,
			"no open reception",
		},
		{
			"Invalid PVZ ID",
			"invalid",
			func(m *mocks.MockStorage) {},
			http.StatusBadRequest,
			"invalid PVZ ID", // Exact match
		},
		{
			"Database error",
			validPVZID,
			func(m *mocks.MockStorage) {
				m.EXPECT().GetOpenReception(gomock.Any(), validPVZID).Return(validReception, nil)
				m.EXPECT().CloseReception(gomock.Any(), validReception.ID).Return(assert.AnError)
			},
			http.StatusInternalServerError,
			"failed to close reception",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStorage := mocks.NewMockStorage(ctrl)
			tt.mockSetup(mockStorage)
			srv.storage = mockStorage

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/pvz/"+tt.pvzID+"/close_last_reception", nil)
			req.Header.Set("Authorization", "Bearer "+employeeToken)

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

func TestDeleteLastProduct(t *testing.T) {
	srv, _, _, employeeToken := setupTest(t)

	validPVZID := uuid.NewString()
	validReception := &models.Reception{
		ID:     uuid.NewString(),
		PVZID:  validPVZID,
		Status: "in_progress",
	}
	validProduct := &models.Product{
		ID:          uuid.NewString(),
		ReceptionID: validReception.ID,
		Type:        "электроника",
		DateTime:    time.Now(),
	}

	tests := []struct {
		name         string
		pvzID        string
		mockSetup    func(*mocks.MockStorage)
		wantStatus   int
		wantErrorMsg string
	}{
		{
			"Success",
			validPVZID,
			func(m *mocks.MockStorage) {
				m.EXPECT().GetOpenReception(gomock.Any(), validPVZID).Return(validReception, nil)
				m.EXPECT().GetLastProduct(gomock.Any(), validReception.ID).Return(validProduct, nil)
				m.EXPECT().DeleteProduct(gomock.Any(), validProduct.ID).Return(nil)
			},
			http.StatusOK,
			"",
		},
		{
			"No open reception",
			validPVZID,
			func(m *mocks.MockStorage) {
				m.EXPECT().GetOpenReception(gomock.Any(), validPVZID).Return(nil, drivers.ErrNotFound)
			},
			http.StatusBadRequest,
			"no open reception",
		},
		{
			"No products",
			validPVZID,
			func(m *mocks.MockStorage) {
				m.EXPECT().GetOpenReception(gomock.Any(), validPVZID).Return(validReception, nil)
				m.EXPECT().GetLastProduct(gomock.Any(), validReception.ID).Return(nil, drivers.ErrNotFound)
			},
			http.StatusBadRequest,
			"no products to delete",
		},
		{
			"Database error",
			validPVZID,
			func(m *mocks.MockStorage) {
				m.EXPECT().GetOpenReception(gomock.Any(), validPVZID).Return(validReception, nil)
				m.EXPECT().GetLastProduct(gomock.Any(), validReception.ID).Return(validProduct, nil)
				m.EXPECT().DeleteProduct(gomock.Any(), validProduct.ID).Return(assert.AnError)
			},
			http.StatusInternalServerError,
			"failed to delete product",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockStorage := mocks.NewMockStorage(ctrl)
			tt.mockSetup(mockStorage)
			srv.storage = mockStorage

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/pvz/"+tt.pvzID+"/delete_last_product", nil)
			req.Header.Set("Authorization", "Bearer "+employeeToken)

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

func TestNewServer(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := mocks.NewMockStorage(ctrl)
	testConfig := config.Config{
		Secret: "test-secret",
	}

	opts := ServerOpts{
		Storage: mockStorage,
		Config:  testConfig,
	}

	srv := NewServer(opts)

	assert.NotNil(t, srv)
	assert.NotNil(t, srv.router)
	assert.Equal(t, mockStorage, srv.storage)
	assert.Equal(t, testConfig, srv.config)
}

func TestServer_Run(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := mocks.NewMockStorage(ctrl)
	testConfig := config.Config{
		Listen: ":0", // используем :0 для автоматического выбора порта
	}

	srv := NewServer(ServerOpts{
		Storage: mockStorage,
		Config:  testConfig,
	})

	// Тестируем запуск сервера
	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Run(testConfig.Listen)
	}()

	// Проверяем что сервер запустился
	select {
	case err := <-errChan:
		t.Fatalf("Server failed to start: %v", err)
	default:
		// Сервер запущен успешно
	}

	// Останавливаем сервер (можно добавить graceful shutdown в реализацию)
	// В реальном тесте нужно добавить механизм остановки сервера
}

func TestServer_RunGRPC(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := mocks.NewMockStorage(ctrl)
	testConfig := config.Config{}

	srv := NewServer(ServerOpts{
		Storage: mockStorage,
		Config:  testConfig,
	})

	t.Run("Successful startup", func(t *testing.T) {
		listener, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		defer listener.Close()

		port := listener.Addr().(*net.TCPAddr).Port
		addr := fmt.Sprintf(":%d", port)

		errChan := make(chan error, 1)
		go func() {
			errChan <- srv.RunGRPC(addr)
		}()

		// Даем серверу время на запуск
		select {
		case err := <-errChan:
			t.Fatalf("gRPC server failed to start: %v", err)
		default:
			// Проверяем что порт слушается
			conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
			if err != nil {
				t.Fatalf("Failed to dial gRPC server: %v", err)
			}
			conn.Close()
		}
	})

	t.Run("Invalid address", func(t *testing.T) {
		err := srv.RunGRPC("invalid-address")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "address")
	})
}

// Дополнительные тесты для проверки регистрации обработчиков
func TestSetupRoutes(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := mocks.NewMockStorage(ctrl)
	testConfig := config.Config{
		Secret: "test-secret",
	}

	srv := NewServer(ServerOpts{
		Storage: mockStorage,
		Config:  testConfig,
	})

	srv.SetupRoutes()

	// Проверяем что роуты зарегистрированы
	routes := srv.router.Routes()
	assert.NotEmpty(t, routes)
}

type mockStorage struct {
	storage.Storage
	pvzs []*models.PVZ
	err  error
}

func (m *mockStorage) GetPVZs(ctx context.Context, filter models.PVZFilter) ([]*models.PVZ, error) {
	return m.pvzs, m.err
}

func TestGetPVZList(t *testing.T) {
	now := time.Now()
	zeroTime := time.Time{}

	tests := []struct {
		name    string
		store   *mockStorage
		want    *pvz_v1.GetPVZListResponse
		wantErr bool
	}{
		{
			name: "success case",
			store: &mockStorage{
				pvzs: []*models.PVZ{
					{
						ID:               "1",
						City:             "Moscow",
						RegistrationDate: now,
					},
				},
			},
			want: &pvz_v1.GetPVZListResponse{
				Pvzs: []*pvz_v1.PVZ{
					{
						Id:               "1",
						City:             "Moscow",
						RegistrationDate: timestamppb.New(now),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "empty result",
			store: &mockStorage{
				pvzs: []*models.PVZ{},
			},
			want: &pvz_v1.GetPVZListResponse{
				Pvzs: []*pvz_v1.PVZ{},
			},
			wantErr: false,
		},
		{
			name: "storage error",
			store: &mockStorage{
				err: assert.AnError,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "zero time",
			store: &mockStorage{
				pvzs: []*models.PVZ{
					{
						ID:               "2",
						City:             "SPb",
						RegistrationDate: zeroTime,
					},
				},
			},
			want: &pvz_v1.GetPVZListResponse{
				Pvzs: []*pvz_v1.PVZ{
					{
						Id:               "2",
						City:             "SPb",
						RegistrationDate: timestamppb.New(zeroTime), // Ожидаем Timestamp для нулевого времени
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := NewServer(ServerOpts{Storage: tt.store})
			got, err := srv.GetPVZList(context.Background(), &pvz_v1.GetPVZListRequest{})

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, len(tt.want.Pvzs), len(got.Pvzs))

			for i, wantPVZ := range tt.want.Pvzs {
				gotPVZ := got.Pvzs[i]
				assert.Equal(t, wantPVZ.Id, gotPVZ.Id)
				assert.Equal(t, wantPVZ.City, gotPVZ.City)

				require.NotNil(t, gotPVZ.RegistrationDate)
				assert.True(t,
					wantPVZ.RegistrationDate.AsTime().Equal(gotPVZ.RegistrationDate.AsTime()),
					"expected: %v, got: %v",
					wantPVZ.RegistrationDate.AsTime(),
					gotPVZ.RegistrationDate.AsTime(),
				)
			}
		})
	}
}

func TestGRPCServiceRegistration(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := mocks.NewMockStorage(ctrl)
	testConfig := config.Config{
		ListenGRPC: ":0",
	}

	srv := NewServer(ServerOpts{
		Storage: mockStorage,
		Config:  testConfig,
	})

	// Создаем тестовый gRPC сервер
	grpcServer := grpc.NewServer()
	pvz_v1.RegisterPVZServiceServer(grpcServer, srv)

	// Проверяем что сервис зарегистрирован
	services := grpcServer.GetServiceInfo()
	_, ok := services["pvz.v1.PVZService"]
	assert.True(t, ok, "PVZService not registered")
}

const (
	testDBURL      = "postgres://admin:admin@localhost:5432/pvztest?sslmode=disable"
	migrationsPath = "file://../../migrations"
)

func setupTestDB(t *testing.T) (*sql.DB, func()) {
	// Создаем подключение к тестовой БД
	db, err := sql.Open(storage.PgxDriverType, testDBURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}

	// Применяем миграции
	m, err := migrate.New(migrationsPath, testDBURL)
	if err != nil {
		t.Fatalf("Failed to create migrate instance: %v", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("Failed to apply migrations: %v", err)
	}

	// Функция для очистки после тестов
	cleanup := func() {
		// Откатываем миграции
		if err := m.Drop(); err != nil && err != migrate.ErrNoChange {
			t.Logf("Warning: failed to rollback migrations: %v", err)
		}
		db.Close()
	}

	return db, cleanup
}

func TestServerIntegration(t *testing.T) {
	// Настраиваем тестовую БД
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Создаем хранилище
	store := drivers.NewPostgresStorage(db, testDBURL)
	// Create test config
	cfg := config.Config{
		Secret: "test-secret",
	}

	// Create server
	srv := NewServer(ServerOpts{
		Storage: store,
		Config:  cfg,
	})

	srv.SetupRoutes()

	// Test user registration and login
	t.Run("User registration and login", func(t *testing.T) {
		// Register new user
		registerData := map[string]string{
			"email":    "test@example.com",
			"password": "password123",
			"role":     "employee",
		}
		registerBody, _ := json.Marshal(registerData)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(registerBody))
		req.Header.Set("Content-Type", "application/json")

		srv.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code)

		// Login with registered user
		loginData := map[string]string{
			"email":    "test@example.com",
			"password": "password123",
		}
		loginBody, _ := json.Marshal(loginData)

		w = httptest.NewRecorder()
		req, _ = http.NewRequest("POST", "/login", bytes.NewBuffer(loginBody))
		req.Header.Set("Content-Type", "application/json")

		srv.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var loginResponse map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &loginResponse)
		assert.NoError(t, err)
		assert.NotEmpty(t, loginResponse["token"])
	})

	// Test PVZ operations
	t.Run("PVZ operations", func(t *testing.T) {
		// Get moderator token
		moderatorToken := getAuthToken(srv, "moderator")

		// Create PVZ
		pvzData := models.PVZ{
			City: "Москва",
		}
		pvzBody, _ := json.Marshal(pvzData)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/pvz", bytes.NewBuffer(pvzBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+moderatorToken)

		srv.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code)

		var createdPVZ models.PVZ
		err := json.Unmarshal(w.Body.Bytes(), &createdPVZ)
		assert.NoError(t, err)
		assert.NotEmpty(t, createdPVZ.ID)

		// Get PVZs
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "/pvz", nil)
		req.Header.Set("Authorization", "Bearer "+moderatorToken)

		srv.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var pvzs []models.PVZ
		err = json.Unmarshal(w.Body.Bytes(), &pvzs)
		assert.NoError(t, err)
		assert.Greater(t, len(pvzs), 0)
	})

	// Test reception and product flow
	t.Run("Reception and product flow", func(t *testing.T) {
		// Get employee token
		employeeToken := getAuthToken(srv, "employee")

		// Create PVZ (need moderator token)
		moderatorToken := getAuthToken(srv, "moderator")
		pvzData := models.PVZ{City: "Санкт-Петербург"}
		pvzBody, _ := json.Marshal(pvzData)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/pvz", bytes.NewBuffer(pvzBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+moderatorToken)
		srv.router.ServeHTTP(w, req)

		var pvz models.PVZ
		json.Unmarshal(w.Body.Bytes(), &pvz)

		// Create reception
		receptionData := map[string]string{
			"pvzId": pvz.ID,
		}
		receptionBody, _ := json.Marshal(receptionData)

		w = httptest.NewRecorder()
		req, _ = http.NewRequest("POST", "/receptions", bytes.NewBuffer(receptionBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+employeeToken)

		srv.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code)

		var reception models.Reception
		err := json.Unmarshal(w.Body.Bytes(), &reception)
		assert.NoError(t, err)

		// Add product
		productData := map[string]string{
			"type":  "электроника",
			"pvzId": pvz.ID,
		}
		productBody, _ := json.Marshal(productData)

		w = httptest.NewRecorder()
		req, _ = http.NewRequest("POST", "/products", bytes.NewBuffer(productBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+employeeToken)

		srv.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code)

		var product models.Product
		err = json.Unmarshal(w.Body.Bytes(), &product)
		assert.NoError(t, err)

		// Delete last product
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("POST", "/pvz/"+pvz.ID+"/delete_last_product", nil)
		req.Header.Set("Authorization", "Bearer "+employeeToken)

		srv.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Close reception
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("POST", "/pvz/"+pvz.ID+"/close_last_reception", nil)
		req.Header.Set("Authorization", "Bearer "+employeeToken)

		srv.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	// Test authorization
	t.Run("Authorization checks", func(t *testing.T) {
		// Get employee token
		employeeToken := getAuthToken(srv, "employee")

		// Try to create PVZ as employee (should fail)
		pvzData := models.PVZ{City: "Казань"}
		pvzBody, _ := json.Marshal(pvzData)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/pvz", bytes.NewBuffer(pvzBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+employeeToken)

		srv.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

// Helper function to get auth token
func getAuthToken(srv *Server, role string) string {
	data := map[string]string{"role": role}
	body, _ := json.Marshal(data)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/dummyLogin", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	srv.router.ServeHTTP(w, req)

	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	return response["token"]
}
