package utils

import (
	"golang.org/x/crypto/bcrypt"
)

// HashString hashes a given string using bcrypt.
//
// Parameters:
//   - s: The string to be hashed.
//
// Returns:
//   - A hashed string and an error. Returns an error if hashing fails.
func HashString(s string) (string, error) {
	// hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.DefaultCost)

	return string(hash), err
}

// CheckPasswordHash compares a plaintext password with a hashed password
//
// Parameters:
// - password: The plaintext password to be verified.
// - hash: The hashed password to compare against.
//
// Returns:
// - bool: True if the password matches the hash, false if it does not.
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
