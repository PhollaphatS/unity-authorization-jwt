package middleware

import (
	"github.com/PhollaphatS/unity-authorization-jwt/auth"
	"github.com/gin-gonic/gin"
	"net/http"
)

func JWTMiddleware(tokenType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Use the helper to extract the token
		tokenString, err := auth.ExtractToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		// Validate the token
		var claims interface{}
		if tokenType != "" {
			claims, err = auth.ValidateToken(tokenString, tokenType)
		} else {
			claims, err = auth.DecodeAccessToken(tokenString)
		}

		// Handle validation errors
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		// Attach the claims to the context
		c.Set("claims", claims)

		// Continue processing
		c.Next()
	}
}

func RegenerateTokenMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Use the helper to extract the token
		tokenString, err := auth.ExtractToken(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		// Extract claims from the expired token
		claims, err := auth.ExtractClaimsFromExpiredToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		// Attach the claims to the context
		c.Set("claims", claims)

		// Continue processing
		c.Next()
	}
}
