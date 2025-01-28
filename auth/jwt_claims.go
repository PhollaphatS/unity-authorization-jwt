package auth

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var ErrNoClaimsFound = errors.New("no claims found")
var ErrInvalidClaimsType = errors.New("invalid claims type")
var ErrInvalidCustomerID = errors.New("invalid customer ID format")

func GetCustomerIDFromClaims(c *gin.Context) (uuid.UUID, error) {
	// Get claims from context
	claims, exists := c.Get("claims")
	if !exists {
		return uuid.Nil, ErrNoClaimsFound
	}

	// Type assert claims
	jwtClaim, ok := claims.(*JWTClaims)
	if !ok {
		return uuid.Nil, ErrInvalidClaimsType
	}

	// Parse and validate CustomerID
	customerID, err := uuid.Parse(jwtClaim.CustomerID)
	if err != nil {
		return uuid.Nil, ErrInvalidCustomerID
	}

	return customerID, nil
}
