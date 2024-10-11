package utils

import (
	"golang.org/x/crypto/bcrypt"
)

func HashString(s string) (string, error) {
	// hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost)

	return string(hash), err
}
