package goauth

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Client represents JWT auth module
type Client struct {
	salt   string
	expiry int64
}

// New constructs JWTAuth module
func New(salt string, expiryPeriod int64) (*Client, error) {
	if expiryPeriod <= 0 {
		return nil, errors.New(ErrExpiryLoEqZero)
	}

	return &Client{
		salt:   salt,
		expiry: expiryPeriod,
	}, nil
}

// Encode hashes userID and additional data into access token with expiry
func (auth *Client) Encode(payload AuthPayload) (accessToken string, err error) {
	if payload.UserID == "" {
		return "", errors.New(ErrEmptyUserID)
	}

	expiryUnix := time.Now().UTC().Unix() + auth.expiry

	if err = auth.checkSalt(); err != nil {
		return
	}
	if err = auth.checkExpiry(); err != nil {
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": payload.UserID,
		"expiry":  expiryUnix,
		"data":    payload.Data,
	})
	accessToken, err = token.SignedString([]byte(auth.salt))
	if err != nil {
		return
	}

	return
}

// Decode decodes JWT into user ID and additional data, checks expiration
func (auth *Client) Decode(accessToken string) (payload AuthPayload, err error) {
	if err = auth.checkSalt(); err != nil {
		return
	}
	jwtToken, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf(ErrUnexpectSign, token.Header["alg"])
		}

		return []byte(auth.salt), nil
	})
	if err != nil {
		return
	}

	var expiry int64
	if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok && jwtToken.Valid {
		if userID, ok := claims["user_id"].(string); ok {
			payload.UserID = userID
		}
		if data, ok := claims["data"]; ok {
			payload.Data = data
		}
		if tokenExp, ok := claims["expiry"].(float64); ok {
			expiry = int64(tokenExp)
		}
	}

	if time.Now().UTC().Unix() > expiry {
		return payload, errors.New(ErrExpiredToken)
	}
	if payload.UserID == "" {
		return payload, errors.New(ErrEmptyUserID)
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

func (auth *Client) checkExpiry() (err error) {
	if auth.expiry == 0 || auth.expiry < time.Now().UTC().Unix() {
		err = errors.New(ErrWrongExpiry)
		return
	}

	return
}
