package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

const (
	AccessTokenExp  = 10 * time.Minute   // Access token validity
	RefreshTokenExp = 7 * 24 * time.Hour // Refresh token validity
)

type JWTClaims struct {
	CredentialID string `json:"credential_id"`
	CustomerID   string `json:"customer_id"`
	Role         string `json:"role"`
	jwt.RegisteredClaims
}
