package tests

import (
	"bytes"
	"encoding/json"
	"github.com/chihabderghal/golang-auth/pkg/models"
	"github.com/chihabderghal/golang-auth/pkg/utils"
	tests_setup "github.com/chihabderghal/golang-auth/tests"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestLoginWithExistingUser tests the login functionality for an existing user.
func TestLoginWithExistingUser(t *testing.T) {
	// Set up the test application and create a test database
	app := tests_setup.Setup()
	db, err := tests_setup.CreateTestDB()

	if err != nil {
		t.Fatalf("Failed to set up test database: %v", err)
	}

	// Hash the password for the user to be created
	hash, _ := utils.HashString("pacman123")

	// Create a new user with valid credentials
	user := models.User{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
		Password:  hash,
	}

	// Insert the user into the test database
	err = db.Create(&user).Error
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Create a new HTTP request with the valid user's credentials
	newUser := map[string]string{
		"email":    "john.doe@example.com",
		"password": "pacman123",
	}

	jsonBody, _ := json.Marshal(newUser)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Perform the request to the login endpoint
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}

	// Verify that the response status code is 200 OK for successful login
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Expected status code 200 OK")
}

// TestLoginWithInvalidPassword tests the login functionality with an invalid password for an existing user.
func TestLoginWithInvalidPassword(t *testing.T) {
	// Set up the test application and create a test database
	app := tests_setup.Setup()
	db, err := tests_setup.CreateTestDB()

	if err != nil {
		t.Fatalf("Failed to set up test database: %v", err)
	}

	// Hash the password for the user to be created
	hash, _ := utils.HashString("pacman123")

	// Create a new user with valid credentials
	user := models.User{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
		Password:  hash,
	}

	// Insert the user into the test database
	err = db.Create(&user).Error
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Create a new HTTP request with an invalid password
	newUser := map[string]string{
		"email":    "john.doe@example.com",
		"password": "aptget123", // Incorrect password
	}

	jsonBody, _ := json.Marshal(newUser)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Perform the request to the login endpoint
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}

	// Verify that the response status code is 401 Unauthorized for incorrect password
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Expected status code 401 Unauthorized")
}

// TestLoginWithInvalidEmail tests the login functionality with an invalid email for an existing user.
func TestLoginWithInvalidEmail(t *testing.T) {
	// Set up the test application and create a test database
	app := tests_setup.Setup()
	db, err := tests_setup.CreateTestDB()

	if err != nil {
		t.Fatalf("Failed to set up test database: %v", err)
	}

	// Hash the password for the user to be created
	hash, _ := utils.HashString("pacman123")

	// Create a new user with valid credentials
	user := models.User{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
		Password:  hash,
	}

	// Insert the user into the test database
	err = db.Create(&user).Error
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Create a new HTTP request with an invalid email
	newUser := map[string]string{
		"email":    "john.john@example.com", // Invalid email
		"password": "pacman123",
	}

	jsonBody, _ := json.Marshal(newUser)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Perform the request to the login endpoint
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}

	// Verify that the response status code is 401 Unauthorized for invalid email
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Expected status code 401 Unauthorized")
}

// TestLoginWithNonExistingUser tests the login functionality for a user that does not exist in the database.
func TestLoginWithNonExistingUser(t *testing.T) {
	// Set up the test application and create a test database
	app := tests_setup.Setup()
	_, err := tests_setup.CreateTestDB()

	if err != nil {
		t.Fatalf("Failed to set up test database: %v", err)
	}

	// Create a new HTTP request with a non-existing user
	newUser := map[string]string{
		"email":    "john.doe@example.com", // Non-existing email
		"password": "pacman123",
	}

	jsonBody, _ := json.Marshal(newUser)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Perform the request to the login endpoint
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}

	// Verify that the response status code is 401 Unauthorized for non-existing user
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Expected status code 401 Unauthorized")
}
