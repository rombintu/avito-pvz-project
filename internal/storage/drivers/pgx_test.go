package drivers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/rombintu/avito-pvz-project/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestPostgresStorage(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	storage := NewPostgresStorage(db, "test")

	t.Run("WithTransaction success", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectCommit()

		err := storage.WithTransaction(context.Background(), func(ctx context.Context) error {
			return nil
		})

		assert.NoError(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("WithTransaction rollback on error", func(t *testing.T) {
		mock.ExpectBegin()
		mock.ExpectRollback()

		err := storage.WithTransaction(context.Background(), func(ctx context.Context) error {
			return errors.New("some error")
		})

		assert.Error(t, err)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("CreateUser success", func(t *testing.T) {
		user := &models.User{
			ID:       "user1",
			Email:    "test@example.com",
			Password: "password",
			Role:     "employee",
		}

		mock.ExpectExec("INSERT INTO users").
			WithArgs(user.ID, user.Email, user.Password, user.Role, sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := storage.CreateUser(context.Background(), user)
		assert.NoError(t, err)
	})

	t.Run("CreateUser duplicate email", func(t *testing.T) {
		user := &models.User{
			ID:       "user1",
			Email:    "duplicate@example.com",
			Password: "password",
			Role:     "employee",
		}

		mock.ExpectExec("INSERT INTO users").
			WillReturnError(&pq.Error{Code: "23505"})

		err := storage.CreateUser(context.Background(), user)
		assert.Equal(t, ErrDuplicateEmail, err)
	})

	t.Run("GetUserByEmail success", func(t *testing.T) {
		expectedUser := &models.User{
			ID:       "user1",
			Email:    "test@example.com",
			Password: "password",
			Role:     "employee",
		}

		rows := sqlmock.NewRows([]string{"id", "email", "password", "role"}).
			AddRow(expectedUser.ID, expectedUser.Email, expectedUser.Password, expectedUser.Role)

		mock.ExpectQuery("SELECT id, email, password, role").
			WithArgs(expectedUser.Email).
			WillReturnRows(rows)

		user, err := storage.GetUserByEmail(context.Background(), expectedUser.Email)
		assert.NoError(t, err)
		assert.Equal(t, expectedUser, user)
	})

	t.Run("GetUserByEmail not found", func(t *testing.T) {
		mock.ExpectQuery("SELECT id, email, password, role").
			WithArgs("nonexistent@example.com").
			WillReturnError(sql.ErrNoRows)

		_, err := storage.GetUserByEmail(context.Background(), "nonexistent@example.com")
		assert.Equal(t, ErrNotFound, err)
	})

	t.Run("CreatePVZ success", func(t *testing.T) {
		pvz := &models.PVZ{
			ID:               "pvz1",
			RegistrationDate: time.Now(),
			City:             "Москва",
		}

		mock.ExpectExec("INSERT INTO pvz").
			WithArgs(pvz.ID, pvz.RegistrationDate, pvz.City).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := storage.CreatePVZ(context.Background(), pvz)
		assert.NoError(t, err)
	})

	t.Run("GetPVZs with filter", func(t *testing.T) {
		now := time.Now()
		filter := models.PVZFilter{
			StartDate: now.Add(-24 * time.Hour),
			EndDate:   now,
			Page:      1,
			Limit:     10,
		}

		expectedPVZs := []*models.PVZ{
			{
				ID:               "pvz1",
				RegistrationDate: now,
				City:             "Москва",
			},
		}

		rows := sqlmock.NewRows([]string{"id", "registration_date", "city"}).
			AddRow(expectedPVZs[0].ID, expectedPVZs[0].RegistrationDate, expectedPVZs[0].City)

		mock.ExpectQuery("SELECT id, registration_date, city").
			WithArgs(filter.StartDate, filter.EndDate, filter.Limit, 0).
			WillReturnRows(rows)

		pvzs, err := storage.GetPVZs(context.Background(), filter)
		assert.NoError(t, err)
		assert.Equal(t, expectedPVZs, pvzs)
	})

	t.Run("CreateReception success", func(t *testing.T) {
		reception := &models.Reception{
			ID:       "rec1",
			DateTime: time.Now(),
			PVZID:    "pvz1",
			Status:   "in_progress",
		}

		mock.ExpectExec("INSERT INTO receptions").
			WithArgs(reception.ID, reception.DateTime, reception.PVZID, reception.Status).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := storage.CreateReception(context.Background(), reception)
		assert.NoError(t, err)
	})

	t.Run("GetOpenReception success", func(t *testing.T) {
		expectedReception := &models.Reception{
			ID:       "rec1",
			DateTime: time.Now(),
			PVZID:    "pvz1",
			Status:   "in_progress",
		}

		rows := sqlmock.NewRows([]string{"id", "date_time", "pvz_id", "status"}).
			AddRow(expectedReception.ID, expectedReception.DateTime, expectedReception.PVZID, expectedReception.Status)

		mock.ExpectQuery("SELECT id, date_time, pvz_id, status").
			WithArgs(expectedReception.PVZID).
			WillReturnRows(rows)

		reception, err := storage.GetOpenReception(context.Background(), expectedReception.PVZID)
		assert.NoError(t, err)
		assert.Equal(t, expectedReception, reception)
	})

	t.Run("CloseReception success", func(t *testing.T) {
		receptionID := "rec1"
		mock.ExpectExec("UPDATE receptions").
			WithArgs(receptionID).
			WillReturnResult(sqlmock.NewResult(0, 1))

		err := storage.CloseReception(context.Background(), receptionID)
		assert.NoError(t, err)
	})

	t.Run("AddProduct success", func(t *testing.T) {
		product := &models.Product{
			ID:          "prod1",
			DateTime:    time.Now(),
			Type:        "электроника",
			ReceptionID: "rec1",
		}

		mock.ExpectExec("INSERT INTO products").
			WithArgs(product.ID, product.DateTime, product.Type, product.ReceptionID).
			WillReturnResult(sqlmock.NewResult(1, 1))

		err := storage.AddProduct(context.Background(), product)
		assert.NoError(t, err)
	})

	t.Run("GetLastProduct success", func(t *testing.T) {
		expectedProduct := &models.Product{
			ID:          "prod1",
			DateTime:    time.Now(),
			Type:        "электроника",
			ReceptionID: "rec1",
		}

		rows := sqlmock.NewRows([]string{"id", "date_time", "type", "reception_id"}).
			AddRow(expectedProduct.ID, expectedProduct.DateTime, expectedProduct.Type, expectedProduct.ReceptionID)

		mock.ExpectQuery("SELECT id, date_time, type, reception_id").
			WithArgs(expectedProduct.ReceptionID).
			WillReturnRows(rows)

		product, err := storage.GetLastProduct(context.Background(), expectedProduct.ReceptionID)
		assert.NoError(t, err)
		assert.Equal(t, expectedProduct, product)
	})

	t.Run("DeleteProduct success", func(t *testing.T) {
		productID := "prod1"
		mock.ExpectExec("DELETE FROM products").
			WithArgs(productID).
			WillReturnResult(sqlmock.NewResult(0, 1))

		err := storage.DeleteProduct(context.Background(), productID)
		assert.NoError(t, err)
	})

	t.Run("DeleteProduct not found", func(t *testing.T) {
		productID := "nonexistent"
		mock.ExpectExec("DELETE FROM products").
			WithArgs(productID).
			WillReturnResult(sqlmock.NewResult(0, 0))

		err := storage.DeleteProduct(context.Background(), productID)
		assert.Equal(t, ErrNotFound, err)
	})

}

type testDB struct {
	instance testcontainers.Container
	db       *sql.DB
	connStr  string
}

func setupTestDB(t *testing.T) *testDB {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:latest",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "test",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").WithStartupTimeout(10 * time.Second),
	}

	pgContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	host, err := pgContainer.Host(ctx)
	require.NoError(t, err)

	port, err := pgContainer.MappedPort(ctx, "5432")
	require.NoError(t, err)

	connStr := fmt.Sprintf("postgres://test:test@%s:%s/test?sslmode=disable", host, port.Port())

	// Даем время на полную инициализацию
	time.Sleep(500 * time.Millisecond)

	db, err := sql.Open("postgres", connStr)
	require.NoError(t, err)

	// Пытаемся подключиться несколько раз
	var maxAttempts = 5
	for i := 0; i < maxAttempts; i++ {
		err = db.Ping()
		if err == nil {
			break
		}
		time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
	}
	require.NoError(t, err)

	return &testDB{
		instance: pgContainer,
		db:       db,
		connStr:  connStr,
	}
}

func (tdb *testDB) teardown() {
	if tdb.db != nil {
		tdb.db.Close()
	}
	if tdb.instance != nil {
		_ = tdb.instance.Terminate(context.Background())
	}
}

func TestPostgresStorage_Migrate(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.teardown()

	// Создаем временную директорию для миграций
	tmpDir, err := os.MkdirTemp("", "migrations")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Создаем тестовые файлы миграций
	migrations := []struct {
		name    string
		content string
	}{
		{
			name:    "1_init.up.sql",
			content: `CREATE TABLE IF NOT EXISTS test_table (id SERIAL PRIMARY KEY);`,
		},
		{
			name:    "1_init.down.sql",
			content: `DROP TABLE IF EXISTS test_table;`,
		},
	}

	for _, m := range migrations {
		err = os.WriteFile(tmpDir+"/"+m.name, []byte(m.content), 0644)
		require.NoError(t, err)
	}

	// Создаем хранилище
	store := NewPostgresStorage(tdb.db, tdb.connStr)

	t.Run("successful migration", func(t *testing.T) {
		err = store.Migrate("file://" + tmpDir)
		require.NoError(t, err)

		// Проверяем, что миграция применилась
		var exists bool
		err = tdb.db.QueryRow(`SELECT EXISTS (
			SELECT FROM pg_tables
			WHERE schemaname = 'public' AND tablename = 'test_table'
		)`).Scan(&exists)
		require.NoError(t, err)
		require.True(t, exists)
	})
}

func TestPostgresStorage_CleanUp(t *testing.T) {
	tdb := setupTestDB(t)
	defer tdb.teardown()

	// Создаем временную директорию для миграций
	tmpDir, err := os.MkdirTemp("", "migrations")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Создаем тестовые файлы миграций
	migrations := []struct {
		name    string
		content string
	}{
		{
			name:    "1_init.up.sql",
			content: `CREATE TABLE IF NOT EXISTS test_table (id SERIAL PRIMARY KEY);`,
		},
		{
			name:    "1_init.down.sql",
			content: `DROP TABLE IF EXISTS test_table;`,
		},
	}

	for _, m := range migrations {
		err = os.WriteFile(tmpDir+"/"+m.name, []byte(m.content), 0644)
		require.NoError(t, err)
	}

	// Создаем хранилище
	store := NewPostgresStorage(tdb.db, tdb.connStr)

	t.Run("successful cleanup", func(t *testing.T) {
		// Сначала применяем миграции
		err = store.Migrate("file://" + tmpDir)
		require.NoError(t, err)

		// Затем очищаем
		err = store.CleanUp("file://" + tmpDir)
		require.NoError(t, err)

		// Проверяем, что таблицы удалены
		var exists bool
		err = tdb.db.QueryRow(`SELECT EXISTS (
			SELECT FROM pg_tables
			WHERE schemaname = 'public' AND tablename = 'test_table'
		)`).Scan(&exists)
		require.NoError(t, err)
		require.False(t, exists)
	})
}
