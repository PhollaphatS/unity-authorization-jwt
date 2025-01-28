package auth

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"net/http"
)

func GetCustomerIDFromClaims(c *gin.Context) (uuid.UUID, error) {
	// Get claims from context
	claims, exists := c.Get("claims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: no claims found"})
		c.Abort()
		return uuid.Nil, fmt.Errorf("no claims found")
	}

	// Type assert claims
	jwtClaim, ok := claims.(*JWTClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: invalid claims"})
		c.Abort()
		return uuid.Nil, fmt.Errorf("invalid claims type")
	}

	// Parse and validate CustomerID
	customerID, err := uuid.Parse(jwtClaim.CustomerID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid CustomerID"})
		c.Abort()
		return uuid.Nil, fmt.Errorf("invalid customer ID format: %w", err)
	}

	return customerID, nil
}
