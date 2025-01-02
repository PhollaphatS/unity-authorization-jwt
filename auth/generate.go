package auth

import (
	"github.com/PhollaphatS/unity-authorization-jwt/utils"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

func GenerateAccessToken(credentialID, customerID, role string) (string, error) {
	secretKey := utils.GetEnv("JWT_ACCESS_SECRET_KEY", "default-access-secret")
	claims := jwt.MapClaims{
		"credential_id": credentialID,
		"customer_id":   customerID,
		"role":          role,
		"exp":           time.Now().Add(AccessTokenExp).Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secretKey))
}

// GenerateRefreshToken creates a long-lived refresh token.
func GenerateRefreshToken(credentialID string) (string, error) {
	secretKey := utils.GetEnv("JWT_REFRESH_SECRET_KEY", "default-refresh-secret")
	claims := jwt.MapClaims{
		"credential_id": credentialID,
		"exp":           time.Now().Add(RefreshTokenExp).Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secretKey))
}
