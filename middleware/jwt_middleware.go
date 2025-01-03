package middleware

import (
	"github.com/PhollaphatS/unity-authorization-jwt/auth"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

func JWTMiddleware(tokenType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the Authorization header
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
			c.Abort() // Stop further processing
			return
		}

		// Strip the Bearer prefix if it exists
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		// Validate the token using the provided token type (if necessary)
		var claims interface{}
		var err error
		if tokenType != "" {
			claims, err = auth.ValidateToken(tokenString, tokenType) // Use your custom validation
		} else {
			claims, err = auth.DecodeAccessToken(tokenString) // Fallback to general decode if no token type is specified
		}

		// Handle error during validation
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort() // Stop further processing
			return
		}

		// Attach the claims to the context for access in handlers
		c.Set("claims", claims)

		// Continue processing the request
		c.Next()
	}
}

func RegenerateTokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the Authorization header
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
			c.Abort()
			return
		}

		// Strip the "Bearer " prefix if it exists
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		// Extract claims from the expired token
		claims, err := auth.ExtractClaimsFromExpiredToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		// Attach the claims to the context
		c.Set("claims", claims)

		// Continue processing the request
		c.Next()
	}
}
