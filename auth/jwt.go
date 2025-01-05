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
func GenerateToken(credentialID, customerID, role string, tokenType string) (string, error) {
	var secretKey string
	var expTime int64

	switch tokenType {
	case "access":
		secretKey = os.Getenv("JWT_ACCESS_SECRET")
		expTime = jwt.NewNumericDate(time.Now().Add(15 * time.Minute)).Unix()
	case "refresh":
		secretKey = os.Getenv("JWT_REFRESH_SECRET")
		expTime = jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)).Unix()
	default:
		return "", fmt.Errorf("invalid token type")
	}

	if secretKey == "" {
		secretKey = "default-secret" // Default for development
	}

	claims := JWTClaims{
		CredentialID: credentialID,
		CustomerID:   customerID,
		Role:         role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(expTime) * time.Second)), // Adding expTime to current time
			IssuedAt:  jwt.NewNumericDate(time.Now()),                                           // Current time
			NotBefore: jwt.NewNumericDate(time.Now()),                                           // Current time
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

func HandleAuthError(c *gin.Context, err error) {
	c.JSON(401, gin.H{"error": err.Error()})
	c.Abort()
}
