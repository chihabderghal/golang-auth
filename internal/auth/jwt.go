package auth

import (
	"github.com/chihabderghal/user-service/pkg/models"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"os"
	"time"
)

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
