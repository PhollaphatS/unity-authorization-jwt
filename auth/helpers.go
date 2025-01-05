package auth

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"strings"
)

func ExtractToken(c *gin.Context) (string, error) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		return "", fmt.Errorf("missing Authorization header")
	}
	// Trim the "Bearer " prefix
	return strings.TrimPrefix(tokenString, "Bearer "), nil
}
