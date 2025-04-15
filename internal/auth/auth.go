package auth

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Role string

const (
	RoleEmployee  Role = "employee"
	RoleModerator Role = "moderator"
)

type Claims struct {
	UserID string `json:"user_id"`
	Role   Role   `json:"role"`
	jwt.StandardClaims
}

func GenerateToken(userID string, role Role, secret string) (string, error) {
	claims := Claims{
		UserID: userID,
		Role:   role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func ValidateToken(tokenString, secret string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
