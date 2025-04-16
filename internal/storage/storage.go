package storage

import (
	"context"
	"database/sql"

	"github.com/rombintu/avito-pvz-project/internal/models"
	"github.com/rombintu/avito-pvz-project/internal/storage/drivers"
)

var (
	PgxDriverType = "postgres"
)

type Storage interface {
	// User operations
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)

	// PVZ operations
	CreatePVZ(ctx context.Context, pvz *models.PVZ) error
	GetPVZs(ctx context.Context, filter models.PVZFilter) ([]*models.PVZ, error)

	// Reception operations
	CreateReception(ctx context.Context, reception *models.Reception) error
	GetOpenReception(ctx context.Context, pvzID string) (*models.Reception, error)
	CloseReception(ctx context.Context, receptionID string) error

	// Product operations
	AddProduct(ctx context.Context, product *models.Product) error
	GetLastProduct(ctx context.Context, receptionID string) (*models.Product, error)
	DeleteProduct(ctx context.Context, productID string) error

	// Automigrate and etc.
	Migrate(mpath string) error
	CleanUp(mpath string) error
}

type StorageOpts struct {
	Database   *sql.DB
	DriverType string
	DriverPath string
}

func NewStorage(opts StorageOpts) Storage {
	switch opts.DriverType {
	case PgxDriverType:
		return drivers.NewPostgresStorage(opts.Database, opts.DriverPath)
	}
	return nil
}
