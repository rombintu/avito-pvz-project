package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rombintu/avito-pvz-project/internal/auth"
	"github.com/rombintu/avito-pvz-project/internal/config"
	"github.com/rombintu/avito-pvz-project/internal/metrics"
	"github.com/rombintu/avito-pvz-project/internal/models"
	pvz_v1 "github.com/rombintu/avito-pvz-project/internal/proto"
	"github.com/rombintu/avito-pvz-project/internal/storage"
	"github.com/rombintu/avito-pvz-project/internal/storage/drivers"
	"github.com/rombintu/avito-pvz-project/pkg/middleware"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	TCP = "tcp"
)

type Server struct {
	pvz_v1.UnimplementedPVZServiceServer
	router  *gin.Engine
	storage storage.Storage
	config  config.Config
}

type ServerOpts struct {
	Storage storage.Storage
	Config  config.Config
}

func NewServer(opts ServerOpts) *Server {
	return &Server{
		router:  gin.Default(),
		storage: opts.Storage,
		config:  opts.Config,
	}
}

func (s *Server) Run(addr string) error {
	s.SetupRoutes()

	go func() {
		metricsServer := &http.Server{
			Addr:    ":9000",
			Handler: promhttp.Handler(),
		}
		slog.Info("Listening and serving Prometheus", slog.String("addr", ":9000"))
		metricsServer.ListenAndServe()
	}()

	return s.router.Run(addr)
}

func (s *Server) RunGRPC(addr string) error {
	listen, err := net.Listen(TCP, addr)
	if err != nil {
		return err
	}
	service := grpc.NewServer()
	pvz_v1.RegisterPVZServiceServer(service, s)
	slog.Info("Listening and serving GRPC", slog.String("addr", addr))
	return service.Serve(listen)
}

func (s *Server) SetupRoutes() {
	// Add Prometheus middleware
	s.router.Use(PrometheusMiddleware())

	// Public routes
	s.router.POST("/dummyLogin", s.dummyLogin)
	s.router.POST("/register", s.register)
	s.router.POST("/login", s.login)

	// Authenticated routes
	authGroup := s.router.Group("/")
	authGroup.Use(middleware.AuthMiddleware(s.config.Secret))
	{
		authGroup.POST("/pvz", s.createPVZ)
		authGroup.GET("/pvz", s.getPVZs)
		authGroup.POST("/receptions", s.createReception)
		authGroup.POST("/products", s.addProduct)
		authGroup.POST("/pvz/:pvzId/close_last_reception", s.closeLastReception)
		authGroup.POST("/pvz/:pvzId/delete_last_product", s.deleteLastProduct)
	}
}

// dummyLogin handles dummy login requests
func (s *Server) dummyLogin(c *gin.Context) {
	var req struct {
		Role string `json:"role"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if req.Role != "employee" && req.Role != "moderator" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role"})
		return
	}

	token, err := auth.GenerateToken(uuid.New().String(), auth.Role(req.Role), s.config.Secret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

// register handles user registration
func (s *Server) register(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=8"`
		Role     string `json:"role" binding:"required,oneof=employee moderator"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user := &models.User{
		ID:       uuid.New().String(),
		Email:    req.Email,
		Password: req.Password, // Note: для упрощения, без хеширования
		Role:     req.Role,
	}

	if err := s.storage.CreateUser(c.Request.Context(), user); err != nil {
		if errors.Is(err, drivers.ErrDuplicateEmail) {
			c.JSON(http.StatusConflict, gin.H{"error": "email already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":    user.ID,
		"email": user.Email,
		"role":  user.Role,
	})
}

// login handles user login
func (s *Server) login(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := s.storage.GetUserByEmail(c.Request.Context(), req.Email)
	if err != nil {
		if errors.Is(err, drivers.ErrNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user"})
		return
	}

	// Note: In production, use proper password hashing comparison!
	if user.Password != req.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := auth.GenerateToken(user.ID, auth.Role(user.Role), s.config.Secret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

// createPVZ handles PVZ creation (moderator only)
func (s *Server) createPVZ(c *gin.Context) {
	claims, exists := c.Get("claims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "claims not found"})
		return
	}

	authClaims, ok := claims.(*auth.Claims)
	if !ok || authClaims.Role != auth.RoleModerator {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	var pvz models.PVZ
	if err := c.ShouldBindJSON(&pvz); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate city
	validCities := map[string]bool{"Москва": true, "Санкт-Петербург": true, "Казань": true}
	if !validCities[pvz.City] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid city"})
		return
	}

	pvz.ID = uuid.New().String()
	pvz.RegistrationDate = time.Now()

	if err := s.storage.CreatePVZ(c.Request.Context(), &pvz); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create PVZ"})
		return
	}

	// After successful PVZ creation
	metrics.PVZCreated.Inc()

	c.JSON(http.StatusCreated, pvz)
}

// getPVZs retrieves PVZs with filtering
func (s *Server) getPVZs(c *gin.Context) {
	claims := c.MustGet("claims").(*auth.Claims)
	if claims.Role != auth.RoleEmployee && claims.Role != auth.RoleModerator {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	var filter models.PVZFilter
	if err := c.ShouldBindQuery(&filter); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set default values if not provided
	if filter.Limit == 0 {
		filter.Limit = 10
	}
	if filter.Page == 0 {
		filter.Page = 1
	}

	pvzs, err := s.storage.GetPVZs(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get PVZs"})
		return
	}

	c.JSON(http.StatusOK, pvzs)
}

// createReception handles reception creation (employee only)
func (s *Server) createReception(c *gin.Context) {
	claims := c.MustGet("claims").(*auth.Claims)
	if claims.Role != auth.RoleEmployee {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	var req struct {
		PVZID string `json:"pvzId" binding:"required,uuid"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	reception := &models.Reception{
		ID:       uuid.New().String(),
		DateTime: time.Now(),
		PVZID:    req.PVZID,
		Status:   "in_progress",
	}

	if err := s.storage.CreateReception(c.Request.Context(), reception); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create reception"})
		return
	}

	// After successful reception creation
	metrics.ReceptionsCreated.Inc()

	c.JSON(http.StatusCreated, reception)
}

// addProduct handles product addition to reception (employee only)
func (s *Server) addProduct(c *gin.Context) {
	claims := c.MustGet("claims").(*auth.Claims)
	if claims.Role != auth.RoleEmployee {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	var req struct {
		Type  string `json:"type" binding:"required,oneof=электроника одежда обувь"`
		PVZID string `json:"pvzId" binding:"required,uuid"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get open reception for this PVZ
	reception, err := s.storage.GetOpenReception(c.Request.Context(), req.PVZID)
	if err != nil {
		if errors.Is(err, drivers.ErrNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no open reception found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get reception"})
		return
	}

	product := &models.Product{
		ID:          uuid.New().String(),
		DateTime:    time.Now(),
		Type:        req.Type,
		ReceptionID: reception.ID,
	}

	if err := s.storage.AddProduct(c.Request.Context(), product); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to add product"})
		return
	}

	// After successful product addition
	metrics.ProductsAdded.Inc()

	c.JSON(http.StatusCreated, product)
}

// closeLastReception closes the last open reception (employee only)
func (s *Server) closeLastReception(c *gin.Context) {
	claims := c.MustGet("claims").(*auth.Claims)
	if claims.Role != auth.RoleEmployee {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	pvzID := c.Param("pvzId")
	if _, err := uuid.Parse(pvzID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid PVZ ID"})
		return
	}

	// Get open reception
	reception, err := s.storage.GetOpenReception(c.Request.Context(), pvzID)
	if err != nil {
		if errors.Is(err, drivers.ErrNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no open reception found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get reception"})
		return
	}

	if err := s.storage.CloseReception(c.Request.Context(), reception.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to close reception"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "reception closed successfully"})
}

// deleteLastProduct deletes the last added product (employee only, LIFO)
func (s *Server) deleteLastProduct(c *gin.Context) {
	claims := c.MustGet("claims").(*auth.Claims)
	if claims.Role != auth.RoleEmployee {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	pvzID := c.Param("pvzId")
	if _, err := uuid.Parse(pvzID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid PVZ ID"})
		return
	}

	// Get open reception
	reception, err := s.storage.GetOpenReception(c.Request.Context(), pvzID)
	if err != nil {
		if errors.Is(err, drivers.ErrNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no open reception found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get reception"})
		return
	}

	// Get last product
	product, err := s.storage.GetLastProduct(c.Request.Context(), reception.ID)
	if err != nil {
		if errors.Is(err, drivers.ErrNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no products to delete"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get product"})
		return
	}

	if err := s.storage.DeleteProduct(c.Request.Context(), product.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete product"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "product deleted successfully"})
}

// GRPC
func (s *Server) GetPVZList(ctx context.Context, in *pvz_v1.GetPVZListRequest) (*pvz_v1.GetPVZListResponse, error) {
	pvzs, err := s.storage.GetPVZs(ctx, models.PVZFilter{})
	if err != nil {
		return nil, err
	}

	var r pvz_v1.GetPVZListResponse

	for _, p := range pvzs {
		r.Pvzs = append(r.Pvzs, &pvz_v1.PVZ{
			Id:               p.ID,
			City:             p.City,
			RegistrationDate: timestamppb.New(p.RegistrationDate),
		})
	}
	return &r, nil
}
