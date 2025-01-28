package auth

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"net/http"
)

var ErrNoClaimsFound = errors.New("no claims found")
var ErrInvalidClaimsType = errors.New("invalid claims type")
var ErrInvalidCustomerID = errors.New("invalid customer ID format")

var errorResponses = map[error]gin.H{
	ErrNoClaimsFound:     {"error": "Unauthorized: no claims found"},
	ErrInvalidClaimsType: {"error": "Unauthorized: invalid claims"},
	ErrInvalidCustomerID: {"error": "Invalid CustomerID format"},
}

var statusCodes = map[error]int{
	ErrNoClaimsFound:     http.StatusUnauthorized,
	ErrInvalidClaimsType: http.StatusUnauthorized,
	ErrInvalidCustomerID: http.StatusBadRequest,
}

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

func HandleClaimsError(c *gin.Context, err error) {
	status := statusCodes[err]
	if status == 0 {
		status = http.StatusInternalServerError
	}
	c.JSON(status, errorResponses[err])
}
