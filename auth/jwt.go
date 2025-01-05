package auth

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"strings"
	"time"
)

type JWTClaims struct {
	CredentialID string `json:"credential_id"`
	CustomerID   string `json:"customer_id"`
	Role         string `json:"role"`
	jwt.RegisteredClaims
}

// ExtractAndValidateToken extracts and validates JWT from the request
func ExtractAndValidateToken(c *gin.Context, tokenType string) (*JWTClaims, error) {
	token, err := ExtractToken(c)
	if err != nil {
		return nil, err
	}

	claims, err := ValidateToken(token, tokenType)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// ExtractToken gets the token from the Authorization header
func ExtractToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing Authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("invalid Authorization header format")
	}

	return parts[1], nil
}

// ValidateToken validates the JWT token
func ValidateToken(tokenString, tokenType string) (*JWTClaims, error) {
	var secretKey string
	switch tokenType {
	case "access":
		secretKey = os.Getenv("JWT_ACCESS_SECRET")
	case "refresh":
		secretKey = os.Getenv("JWT_REFRESH_SECRET")
	default:
		return nil, fmt.Errorf("invalid token type")
	}

	if secretKey == "" {
		secretKey = "default-secret-change-me" // Default for development
	}

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// GenerateToken creates a new JWT token
func GenerateToken(credentialID, customerID, role, tokenType string) (string, error) {
	// Helper function to get secret and expiration based on token type
	getTokenConfig := func(tokenType string) (string, time.Duration, error) {
		switch tokenType {
		case "access":
			secretKey := os.Getenv("JWT_ACCESS_SECRET")
			if secretKey == "" {
				secretKey = "default-access-secret" // Default for development
			}
			return secretKey, 15 * time.Minute, nil
		case "refresh":
			secretKey := os.Getenv("JWT_REFRESH_SECRET")
			if secretKey == "" {
				secretKey = "default-refresh-secret" // Default for development
			}
			return secretKey, 7 * 24 * time.Hour, nil
		default:
			return "", 0, fmt.Errorf("invalid token type: %s", tokenType)
		}
	}

	// Get secret key and expiration duration
	secretKey, expDuration, err := getTokenConfig(tokenType)
	if err != nil {
		return "", err
	}

	// Define claims based on token type
	var claims jwt.Claims
	switch tokenType {
	case "access":
		claims = JWTClaims{
			CredentialID: credentialID,
			CustomerID:   customerID,
			Role:         role,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(expDuration)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
			},
		}
	case "refresh":
		claims = jwt.MapClaims{
			"credential_id": credentialID,
			"exp":           time.Now().Add(expDuration).Unix(),
			"iat":           time.Now().Unix(),
		}
	default:
		return "", fmt.Errorf("unsupported token type")
	}

	// Generate token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

func HandleAuthError(c *gin.Context, err error) {
	c.JSON(401, gin.H{"error": err.Error()})
	c.Abort()
}
