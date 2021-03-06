package goauth

// Error constants
const (
	ErrEmptySalt    = "Salt is empty string"
	ErrUnexpectSign = "Unexpected signing method: %v"
	ErrExpiredToken = "Access token expired"
	ErrWrongExpiry  = "Wrong expiration date"
)

type decodeResult struct {
	UserID string `json:"user_id"`
	Expiry int64  `json:"expiry"`
}
