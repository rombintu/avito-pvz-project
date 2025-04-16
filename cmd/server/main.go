package main

import (
	"database/sql"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/lib/pq"
	"github.com/rombintu/avito-pvz-project/internal/config"
	"github.com/rombintu/avito-pvz-project/internal/server"
	"github.com/rombintu/avito-pvz-project/internal/storage"
)

func main() {
	cfg := config.NewConfig()
	db, err := sql.Open(storage.PgxDriverType, cfg.DbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	store := storage.NewStorage(storage.StorageOpts{
		Database: db, DriverType: storage.PgxDriverType})
	server := server.NewServer(server.ServerOpts{
		Storage: store,
		// Передаем данные, тк потом не меняем конфигурацию
		Config: cfg,
	})

	// GRPC
	go func() {
		if err := server.RunGRPC(cfg.ListenGRPC); err != nil {
			// TODO: logger
			panic(err)
		}
	}()

	// HTTP
	go func() {
		if err := server.Run(cfg.Listen); err != nil {
			// TODO: logger
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	// Waiting for SIGINT (pkill -2) or SIGTERM
	<-stop
	slog.Info("shutdown server")
}
