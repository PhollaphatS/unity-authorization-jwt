package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/phollaphat/unity-authorization-jwt/auth"
	"net/http"
	"strings"
)

// JWTMiddleware validates access or refresh tokens.
func JWTMiddleware(tokenType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing Authorization header"})
			c.Abort()
			return
		}

		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		claims, err := auth.ValidateToken(tokenString, tokenType)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		// Store claims in context for use in handlers
		c.Set("claims", claims)
		c.Next()
	}
}
