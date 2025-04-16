package main

import (
	"database/sql"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/lib/pq"
	"github.com/rombintu/avito-pvz-project/internal/config"
	"github.com/rombintu/avito-pvz-project/internal/server"
	"github.com/rombintu/avito-pvz-project/internal/storage"
	"github.com/rombintu/avito-pvz-project/lib/logger"
)

func main() {
	// Init logger
	logger.InitLogger(logger.EnvTypeLocal)
	// Init config
	cfg := config.NewConfig()
	// Open database
	db, err := sql.Open(storage.PgxDriverType, cfg.DbPath)
	if err != nil {
		slog.Warn(err.Error())
	}
	defer db.Close()

	// Setup Storage
	store := storage.NewStorage(storage.StorageOpts{
		Database:   db,
		DriverType: storage.PgxDriverType,
		DriverPath: cfg.DbPath,
	})
	// Setup migration
	if err := store.Migrate("file://migrations"); err != nil {
		slog.Warn(err.Error())
	}
	// Init server
	server := server.NewServer(server.ServerOpts{
		Storage: store,
		// Передаем данные, тк потом не меняем конфигурацию
		Config: cfg,
	})

	// GRPC
	go func() {
		if err := server.RunGRPC(cfg.ListenGRPC); err != nil {
			slog.Error(err.Error())
			os.Exit(0)
		}
	}()

	// HTTP
	go func() {
		if err := server.Run(cfg.Listen); err != nil {
			slog.Error(err.Error())
			os.Exit(0)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	// Waiting for SIGINT (pkill -2) or SIGTERM
	<-stop
	slog.Info("shutdown server")
}
