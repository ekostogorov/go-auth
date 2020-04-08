package goauth

// Error constants
const (
	ErrEmptySalt      = "salt is empty string"
	ErrUnexpectSign   = "unexpected signing method: %v"
	ErrExpiredToken   = "access token expired"
	ErrWrongExpiry    = "wrong expiration date"
	ErrEmptyUserID    = "empty user id"
	ErrExpiryLoEqZero = "expiry period must be greater than zero"
)

type decodeResult struct {
	UserID string      `json:"user_id"`
	Expiry int64       `json:"expiry"`
	Data   interface{} `json:"data"`
}

// AuthPayload represents model used as argument for
// user ID and any additional info in Encode and Decode methods
type AuthPayload struct {
	UserID string
	Data   interface{}
}
