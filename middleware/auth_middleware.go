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

func AuthWithoutExpTimeMiddleware(config AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract the request path without query parameters
		requestPath := c.FullPath()

		// Skip authentication for specified paths
		for _, path := range config.SkipPaths {
			artyarty
			if requestPath == path {
				c.Next() // Skip authentication and continue to the next handler
				return
			}

		}

		// Extract token from the Authorization header
		token, err := auth.ExtractToken(c)
		if err != nil {
			c.JSON(401, gin.H{"error": "Unauthorized: " + err.Error()})
			c.Abort()
			return
		}

		// Validate the token without checking the expiration
		claims, err := auth.ValidateTokenIgnoreExpiry(token, "access")
		if err != nil {
			c.JSON(401, gin.H{"error": "Unauthorized: " + err.Error()})
			c.Abort()
			return
		}

		// Check if the required role matches (if any)
		if config.RequireRole != "" && claims.Role != config.RequireRole {
			c.JSON(403, gin.H{"error": "Forbidden: insufficient role"})
			c.Abort()
			return
		}

		// Store the claims in the context for further use
		c.Set("claims", claims)
		c.Next()
	}
}
