package goauth

import (
	"errors"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// Client represents JWT auth module
type Client struct {
	salt   string
	expiry int64
}

// New constructs JWTAuth module
func New(salt string, expiryDate int64) *Client {
	return &Client{
		salt:   salt,
		expiry: expiryDate,
	}
}

// Encode hashes userID into access token with expiry
func (auth *Client) Encode(userID string) (accessToken string, err error) {
	if err = auth.checkSalt(); err != nil {
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"expiry":  auth.expiry,
	})
	accessToken, err = token.SignedString([]byte(auth.salt))
	if err != nil {
		return
	}

	return
}

// Decode decodes JWT into user ID, checks expiration
func (auth *Client) Decode(accessToken string) (userID string, err error) {
	var result decodeResult

	jwtToken, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf(ErrUnexpectSign, token.Header["alg"])
		}

		return []byte(auth.salt), nil
	})
	if err != nil {
		return
	}

	if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok && jwtToken.Valid {
		result.UserID = claims["user_id"].(string)
		result.Expiry = int64(claims["expiry"].(float64))
	}

	userID = result.UserID
	if time.Now().UTC().Unix() > result.Expiry {
		err = errors.New(ErrExpiredToken)
		return
	}

	return
}

func (auth *Client) checkSalt() (err error) {
	if len(auth.salt) == 0 {
		err = errors.New(ErrEmptySalt)
		return
	}

	return
}
