package auth

import (
	"fmt"
	"github.com/PhollaphatS/unity-authorization-jwt/utils"
	"github.com/golang-jwt/jwt/v5"
)

func DecodeAccessToken(accessToken string) (map[string]interface{}, error) {
	// Get the JWT secret key from the environment variable
	secretKey := utils.GetEnv("JWT_ACCESS_SECRET_KEY", "default-access-secret")

	// Parse the token using the JWT library
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token is signed with the correct method (HMAC)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Return the key for verification (secret key)
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Extract claims from the token if valid
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Convert claims to a map for easy access
		claimsMap := make(map[string]interface{})
		for key, value := range claims {
			claimsMap[key] = value
		}
		return claimsMap, nil
	}

	return nil, ErrUnauthorized
}
