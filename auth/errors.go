package auth

import "errors"

var (
	ErrTokenExpired = errors.New("token has expired")
	ErrInvalidToken = errors.New("invalid token")
	ErrMissingToken = errors.New("missing token")
	ErrUnauthorized = errors.New("unauthorized access")
)
