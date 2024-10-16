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
	"os"
	"testing"
)

// TestRegisterUserAndValidateTokenClaims tests the user registration process
// by sending a request to /api/auth/register with valid user data. It verifies
// that the response status code is 201 Created, saves the user in the database,
// and checks the JWT tokens in the cookies for correct claims, specifically
// validating the 'sub' and 'email' claims.
func TestRegisterUserAndValidateTokenClaims(t *testing.T) {
	// Initialize the test environment, setting up the Fiber app and connecting to the test database.
	app := tests_setup.Setup()
	db, err := tests_setup.CreateTestDB()

	if err != nil {
		// Terminate the test if the test database setup fails.
		t.Fatalf("Failed to set up test database: %v", err)
	}

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

	// Step 3: Get token from cookies and verify if the access and refresh token got the correct claims
	// Here, we assume that the tokens are set in cookies by the registration handler.

	// Retrieve cookies from the response
	cookies := resp.Cookies()
	var accessToken, refreshToken string
	for _, cookie := range cookies {
		if cookie.Name == "accessToken" {
			accessToken = cookie.Value
		}
		if cookie.Name == "refreshToken" {
			refreshToken = cookie.Value
		}
	}

	// Decode the tokens to validate claims (Assuming you have a function to decode the token)
	accessClaims, err := utils.ParseJwt(accessToken, os.Getenv("AT_SECRET")) // Implement this function to extract claims
	if err != nil {
		t.Fatalf("Failed to decode access token: %v", err)
	}

	refreshClaims, err := utils.ParseJwt(refreshToken, os.Getenv("RT_SECRET")) // Implement this function to extract claims
	if err != nil {
		t.Fatalf("Failed to decode refresh token: %v", err)
	}

	// find the user in the db to compare
	var newUser models.User
	if err := db.Where("email = ?", userBody["email"]).First(&newUser).Error; err != nil {
		t.Fatalf("Failed to find user by email: %v", err)
	}

	accessCookieClaim := uint(accessClaims["sub"].(float64))
	refreshCookieClaim := uint(accessClaims["sub"].(float64))

	// Validate the claims in the access token
	assert.Equal(t, newUser.Email, accessClaims["email"], "Expected email claim in access token does not match")
	assert.Equal(t, newUser.ID, accessCookieClaim, "Expected subject claim in access token does not match")

	// Validate the claims in the refresh token
	assert.Equal(t, newUser.Email, refreshClaims["email"], "Expected email claim in refresh token does not match")
	assert.Equal(t, newUser.ID, refreshCookieClaim, "Expected subject claim in refresh token does not match")
}
