package auth

import (
	"errors"
	"github.com/PhollaphatS/unity-authorization-jwt/utils"
	"github.com/golang-jwt/jwt/v5"
)

// ValidateToken validates an access or refresh token.
func ValidateToken(tokenString, tokenType string) (jwt.MapClaims, error) {
	var secretKey string
	if tokenType == "access_token" {
		secretKey = utils.GetEnv("JWT_ACCESS_SECRET_KEY", "default-access-secret")
	} else if tokenType == "refresh_token" {
		secretKey = utils.GetEnv("JWT_REFRESH_SECRET_KEY", "default-refresh-secret")
	} else {
		return nil, errors.New("invalid token type")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid or expired token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}
