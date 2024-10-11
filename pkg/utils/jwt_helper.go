package utils

import (
	"fmt"
	"github.com/chihabderghal/user-service/pkg/models"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"os"
	"time"
)

// GenerateAccessToken creates a new access token for a given user.
//
// Parameters:
// - user: The user for whom the access token is being generated.
//
// Returns:
// - string: The encoded access token as a string.
func GenerateAccessToken(user models.User) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   user.ID,
		"email": user.Email,
		"exp":   time.Now().Add(time.Minute * 15).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("AT_SECRET")))
	if err != nil {
		log.Fatal(err)
	}

	return tokenString
}

// GenerateRefreshToken creates a new refresh token for a given user.
//
// Parameters:
// - user: The user for whom the refresh token is being generated.
//
// Returns:
// - string: The encoded refresh token as a string.
func GenerateRefreshToken(user models.User) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   user.ID,
		"email": user.Email,
		"exp":   time.Now().Add(time.Hour * 24 * 7 * 4).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("RT_SECRET")))
	if err != nil {
		log.Fatal(err)
	}

	return tokenString
}

// ParseJwt parses a JWT token from a string and verifies it using the provided secret.
//
// Parameters:
// - tokenString: The JWT token as a string that needs to be parsed.
// - secret: The secret key used for signing the token, typically stored in an environment variable.
//
// Returns:
// - jwt.MapClaims: The claims contained in the JWT if parsing and verification are successful.
// - error: An error object if there was an issue parsing or verifying the token.
func ParseJwt(cookie string, secretEnvKey string) (jwt.MapClaims, error) {
	// Parse the  token
	token, err := jwt.Parse(cookie, func(t *jwt.Token) (interface{}, error) {
		// Ensure the token method matches expected signing algorithm
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		// Return the secret key to validate the token signature
		return []byte(secretEnvKey), nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid or expired token")
	}

	// Extract claims from the token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse token claims")
	}

	return claims, nil
}
