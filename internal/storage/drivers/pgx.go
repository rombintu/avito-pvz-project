package drivers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate"
	"github.com/lib/pq"
	"github.com/rombintu/avito-pvz-project/internal/models"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrDuplicateEmail = errors.New("email already exists")
)

// Define context key for transactions
type contextKey int

const (
	CtxTxKey contextKey = iota
)

// Executor interface for both DB and Tx
type Executor interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// PostgresStorage implements storage.Storage with transaction support
type PostgresStorage struct {
	db *sql.DB
}

func NewPostgresStorage(db *sql.DB) *PostgresStorage {
	return &PostgresStorage{db: db}
}

// getExecutor returns current transaction or main DB
func (s *PostgresStorage) getExecutor(ctx context.Context) Executor {
	if tx, ok := ctx.Value(CtxTxKey).(*sql.Tx); ok {
		return tx
	}
	return s.db
}

// WithTransaction executes a function within a database transaction
func (s *PostgresStorage) WithTransaction(ctx context.Context, fn func(context.Context) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			// todo logger
			panic(p)
		}
	}()

	txCtx := context.WithValue(ctx, CtxTxKey, tx)

	if err := fn(txCtx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("tx err: %v, rb err: %w", err, rbErr)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// User operations
func (s *PostgresStorage) CreateUser(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (id, email, password, role, created_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := s.getExecutor(ctx).ExecContext(ctx, query,
		user.ID,
		user.Email,
		user.Password,
		user.Role,
		time.Now(),
	)

	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return ErrDuplicateEmail
		}
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (s *PostgresStorage) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, email, password, role
		FROM users
		WHERE email = $1
	`

	var user models.User
	err := s.getExecutor(ctx).QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Password,
		&user.Role,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}

// PVZ operations
func (s *PostgresStorage) CreatePVZ(ctx context.Context, pvz *models.PVZ) error {
	query := `
		INSERT INTO pvz (id, registration_date, city)
		VALUES ($1, $2, $3)
	`

	_, err := s.getExecutor(ctx).ExecContext(ctx, query,
		pvz.ID,
		pvz.RegistrationDate,
		pvz.City,
	)

	if err != nil {
		return fmt.Errorf("failed to create PVZ: %w", err)
	}

	return nil
}

func (s *PostgresStorage) GetPVZs(ctx context.Context, filter models.PVZFilter) ([]*models.PVZ, error) {
	query := `
		SELECT id, registration_date, city
		FROM pvz
		WHERE 1=1
	`

	var args []interface{}
	argPos := 1

	if !filter.StartDate.IsZero() {
		query += fmt.Sprintf(" AND registration_date >= $%d", argPos)
		args = append(args, filter.StartDate)
		argPos++
	}

	if !filter.EndDate.IsZero() {
		query += fmt.Sprintf(" AND registration_date <= $%d", argPos)
		args = append(args, filter.EndDate)
		argPos++
	}

	query += fmt.Sprintf(" ORDER BY registration_date DESC LIMIT $%d OFFSET $%d", argPos, argPos+1)
	args = append(args, filter.Limit, (filter.Page-1)*filter.Limit)

	rows, err := s.getExecutor(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query PVZs: %w", err)
	}
	defer rows.Close()

	var pvzs []*models.PVZ
	for rows.Next() {
		var pvz models.PVZ
		if err := rows.Scan(
			&pvz.ID,
			&pvz.RegistrationDate,
			&pvz.City,
		); err != nil {
			return nil, fmt.Errorf("failed to scan PVZ: %w", err)
		}
		pvzs = append(pvzs, &pvz)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return pvzs, nil
}

// Reception operations
func (s *PostgresStorage) CreateReception(ctx context.Context, reception *models.Reception) error {
	query := `
		INSERT INTO receptions (id, date_time, pvz_id, status)
		VALUES ($1, $2, $3, $4)
	`

	_, err := s.getExecutor(ctx).ExecContext(ctx, query,
		reception.ID,
		reception.DateTime,
		reception.PVZID,
		reception.Status,
	)

	if err != nil {
		return fmt.Errorf("failed to create reception: %w", err)
	}

	return nil
}

func (s *PostgresStorage) GetOpenReception(ctx context.Context, pvzID string) (*models.Reception, error) {
	query := `
		SELECT id, date_time, pvz_id, status
		FROM receptions
		WHERE pvz_id = $1 AND status = 'in_progress'
		ORDER BY date_time DESC
		LIMIT 1
	`

	var reception models.Reception
	err := s.getExecutor(ctx).QueryRowContext(ctx, query, pvzID).Scan(
		&reception.ID,
		&reception.DateTime,
		&reception.PVZID,
		&reception.Status,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get open reception: %w", err)
	}

	return &reception, nil
}

func (s *PostgresStorage) CloseReception(ctx context.Context, receptionID string) error {
	query := `
		UPDATE receptions
		SET status = 'close'
		WHERE id = $1 AND status = 'in_progress'
	`

	result, err := s.getExecutor(ctx).ExecContext(ctx, query, receptionID)
	if err != nil {
		return fmt.Errorf("failed to close reception: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// Product operations
func (s *PostgresStorage) AddProduct(ctx context.Context, product *models.Product) error {
	query := `
		INSERT INTO products (id, date_time, type, reception_id)
		VALUES ($1, $2, $3, $4)
	`

	_, err := s.getExecutor(ctx).ExecContext(ctx, query,
		product.ID,
		product.DateTime,
		product.Type,
		product.ReceptionID,
	)

	if err != nil {
		return fmt.Errorf("failed to add product: %w", err)
	}

	return nil
}

func (s *PostgresStorage) GetLastProduct(ctx context.Context, receptionID string) (*models.Product, error) {
	query := `
		SELECT id, date_time, type, reception_id
		FROM products
		WHERE reception_id = $1
		ORDER BY date_time DESC
		LIMIT 1
	`

	var product models.Product
	err := s.getExecutor(ctx).QueryRowContext(ctx, query, receptionID).Scan(
		&product.ID,
		&product.DateTime,
		&product.Type,
		&product.ReceptionID,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get last product: %w", err)
	}

	return &product, nil
}

func (s *PostgresStorage) DeleteProduct(ctx context.Context, productID string) error {
	query := `
		DELETE FROM products
		WHERE id = $1
	`

	result, err := s.getExecutor(ctx).ExecContext(ctx, query, productID)
	if err != nil {
		return fmt.Errorf("failed to delete product: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

func (s *PostgresStorage) autoDefaultMigrate(mpath string) error {
	migr, err := migrate.New(
		fmt.Sprintf("file://%s", mpath),
	)
	if err != nil {
		return err
	}
	return migr.Up()
}
