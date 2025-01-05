package middleware

import (
	"github.com/PhollaphatS/unity-authorization-jwt/auth"
	"github.com/gin-gonic/gin"
)

type AuthConfig struct {
	SkipPaths   []string // Paths to skip authentication
	RequireRole string   // Required role for this middleware (optional)
	TokenType   string   // "access" or "refresh"
}

// AuthMiddleware creates a JWT authentication middleware
func AuthMiddleware(config AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip authentication for specified paths
		for _, path := range config.SkipPaths {
			if c.Request.URL.Path == path {
				c.Next()
				return
			}
		}

		// Extract and validate token
		claims, err := auth.ExtractAndValidateToken(c, config.TokenType)
		if err != nil {
			auth.HandleAuthError(c, err)
			return
		}

		// Check role if required
		if config.RequireRole != "" && claims.Role != config.RequireRole {
			c.JSON(403, gin.H{"error": "forbidden: insufficient role"})
			c.Abort()
			return
		}

		// Store claims in context
		c.Set("claims", claims)
		c.Next()
	}
}
