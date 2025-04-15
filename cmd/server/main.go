package main

import (
	"database/sql"
	"log"

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

	if err := server.Run(cfg.Listen); err != nil {
		// todo logger
		log.Fatal(err)
	}
}
