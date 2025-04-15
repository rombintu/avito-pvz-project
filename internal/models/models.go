package models

import (
	"time"
)

type PVZ struct {
	ID               string    `json:"id" db:"id"`
	RegistrationDate time.Time `json:"registrationDate" db:"registration_date"`
	City             string    `json:"city" db:"city"`
}

type Reception struct {
	ID       string    `json:"id" db:"id"`
	DateTime time.Time `json:"dateTime" db:"date_time"`
	PVZID    string    `json:"pvzId" db:"pvz_id"`
	Status   string    `json:"status" db:"status"`
}

type Product struct {
	ID          string    `json:"id" db:"id"`
	DateTime    time.Time `json:"dateTime" db:"date_time"`
	Type        string    `json:"type" db:"type"`
	ReceptionID string    `json:"receptionId" db:"reception_id"`
}

type User struct {
	ID       string `json:"id" db:"id"`
	Email    string `json:"email" db:"email"`
	Password string `json:"-" db:"password"`
	Role     string `json:"role" db:"role"`
}

type PVZFilter struct {
	StartDate time.Time
	EndDate   time.Time
	Page      int
	Limit     int
}
