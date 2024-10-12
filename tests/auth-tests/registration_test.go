package tests

import (
	"bytes"
	"encoding/json"
	"github.com/chihabderghal/user-service/pkg/models"
	"github.com/chihabderghal/user-service/tests"
	"github.com/stretchr/testify/assert"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRegisterUserWithValidData tests the registration of a user with valid data.
// It verifies that the registration request returns a 201 Created status code.
func TestRegisterUserWithValidData(t *testing.T) {
	// Initialize the test environment, setting up the Fiber app and connecting to the test database.
	app := tests_setup.Setup()
	_, err := tests_setup.CreateTestDB()

	if err != nil {
		// Terminate the test if the test database setup fails.
		t.Fatalf("Failed to set up test database: %v", err)
	}

	// Construct a new HTTP request for the user registration endpoint with valid user data.
	userBody := map[string]string{
		"firstName": "John",
		"lastName":  "Doe",
		"email":     "john.doe@example.com",
		"password":  "password123",
	}

	jsonBody, _ := json.Marshal(userBody) // Convert user data to JSON format.

	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Send the registration request to the app and capture the response.
	resp, err := app.Test(req, -1)
	if err != nil {
		// Terminate the test if the request fails to be sent.
		t.Fatalf("Failed to send request: %v", err)
	}

	// Assert that the response status code is 201 Created, indicating successful user registration.
	assert.Equal(t, http.StatusCreated, resp.StatusCode, "Expected status code 201 Created")
}

// TestRegisterUserWithInvalidPassword tests the registration of a user with an invalid password.
// It checks that if the password is too short, the server responds with a 400 Bad Request status.
func TestRegisterUserWithInvalidPassword(t *testing.T) {
	// Initialize the test environment, setting up the Fiber app and connecting to the test database.
	app := tests_setup.Setup()
	_, err := tests_setup.CreateTestDB()

	if err != nil {
		// Terminate the test if the test database setup fails.
		t.Fatalf("Failed to set up test database: %v", err)
	}

	// Construct a new HTTP request for the user registration endpoint with invalid password data.
	// Password "aptget" is intentionally invalid as it doesn't meet the minimum length requirement (< 8 characters).
	userBody := map[string]string{
		"firstName": "John",
		"lastName":  "Doe",
		"email":     "john.doe@example.com",
		"password":  "aptget", // Invalid password length
	}

	jsonBody, _ := json.Marshal(userBody) // Convert user data to JSON format.

	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Send the registration request with invalid password data to the app and capture the response.
	resp, err := app.Test(req, -1)
	if err != nil {
		// Terminate the test if the request fails to be sent.
		t.Fatalf("Failed to send request: %v", err)
	}

	// Assert that the response status code is 400 Bad Request, as the password doesn't meet the requirements.
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "Expected status code 400 bad request")
}

// TestRegisterUserWithInvalidEmail tests the registration of a user with an invalid email format.
// It ensures that when the email is invalid, the response status is 400 Bad Request.
func TestRegisterUserWithInvalidEmail(t *testing.T) {
	// Initialize the test environment by setting up the Fiber app and establishing a connection to the test database.
	app := tests_setup.Setup()
	_, err := tests_setup.CreateTestDB()

	if err != nil {
		// Fail the test if the database setup encounters an error.
		t.Fatalf("Failed to set up test database: %v", err)
	}

	// Construct a new HTTP request for the user registration endpoint with invalid email and password data.
	userBody := map[string]string{
		"firstName": "John",
		"lastName":  "Doe",
		"email":     "john.doe", // Invalid email format
		"password":  "aptget",   // Invalid password length (< 8)
	}

	jsonBody, _ := json.Marshal(userBody) // Convert the user data into JSON format.

	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Execute the registration request with the invalid email and password, capturing the response.
	resp, err := app.Test(req, -1)
	if err != nil {
		// Fail the test if there is an error sending the request.
		t.Fatalf("Failed to send request: %v", err)
	}

	// Assert that the response status code is 400 Bad Request,
	// as both the email format and password length are invalid.
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "Expected status code 400 bad request")
}

// TestRegisterDuplicateUser tests the registration of a user with an email that already exists in the database.
// It verifies that the server responds with a 409 Conflict status when trying to register a duplicate user.
func TestRegisterDuplicateUser(t *testing.T) {
	app := tests_setup.Setup()
	db, err := tests_setup.CreateTestDB()

	if err != nil {
		t.Fatalf("Failed to set up test database: %v", err)
	}

	user := models.User{
		FirstName: "John",
		LastName:  "Doe",
		Email:     "john.doe@example.com",
		Password:  "pacman123",
	}

	err = db.Create(&user).Error
	if err != nil {
		log.Fatalf("Failed to create user: %v", err)
	}

	// Create a new HTTP request with an Invalid user password
	newUser := map[string]string{
		"firstName": "John",
		"lastName":  "Doe",
		"email":     "john.doe@example.com",
		"password":  "pacman123",
	}

	jsonBody, _ := json.Marshal(newUser)

	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	// Perform the request
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}

	// Verify the response status code
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "Expected status code 409 conflict")
}
