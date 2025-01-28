package middleware

import (
	"github.com/PhollaphatS/unity-authorization-jwt/auth"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

type AuthConfig struct {
	SkipPaths   []string // Paths to skip authentication
	RequireRole string   // Required role for this middleware (optional)
	TokenType   string   // "access" or "refresh"
}

// AuthMiddleware creates a JWT authentication middleware
func AuthMiddleware(config AuthConfig) gin.HandlerFunc {
	normalizedSkipPaths := make(map[string]struct{})
	for _, path := range config.SkipPaths {
		normalized := strings.TrimRight(path, "/")
		normalizedSkipPaths[normalized] = struct{}{}
	}

	return func(c *gin.Context) {
		// Normalize request path once
		requestPath := strings.TrimRight(c.Request.URL.Path, "/")

		// Check if path should be skipped using map lookup
		if _, shouldSkip := normalizedSkipPaths[requestPath]; shouldSkip {
			c.Next()
			return
		}

		// Extract and validate token
		claims, err := auth.ExtractAndValidateToken(c, config.TokenType)
		if err != nil {
			auth.HandleAuthError(c, err)
			return
		}

		// Check role if required
		if config.RequireRole != "" && claims.Role != config.RequireRole {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden: insufficient role"})
			c.Abort()
			return
		}

		// Store claims in context
		c.Set("claims", claims)
		c.Next()
	}
}

func AuthWithoutExpTimeMiddleware(config AuthConfig) gin.HandlerFunc {
	normalizedSkipPaths := make(map[string]struct{})
	for _, path := range config.SkipPaths {
		normalized := strings.TrimRight(path, "/")
		normalizedSkipPaths[normalized] = struct{}{}
	}

	return func(c *gin.Context) {
		// Normalize request path once
		requestPath := strings.TrimRight(c.Request.URL.Path, "/")

		// Check if path should be skipped using map lookup
		if _, shouldSkip := normalizedSkipPaths[requestPath]; shouldSkip {
			c.Next()
			return
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
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden: insufficient role"})
			c.Abort()
			return
		}

		// Store claims in context
		c.Set("claims", claims)
		c.Next()
	}
}
