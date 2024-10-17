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

func TestFetchUserProfileWhenUserExists(t *testing.T) {
	// Set up the test application and create a test database
	app := tests_setup.Setup()

	db, err := tests_setup.CreateTestDB()
	if err != nil {
		t.Fatalf("Failed to set up test database: %v", err)
	}

	err = tests_setup.SeedFakeUsers(db, 10)
	if err != nil {
		t.Fatalf("Failed to seed fake users: %v", err)
	}

	// Hash the password for the user to be created
	hash, _ := utils.HashString("pacman123")

	// Create a new user with valid credentials
	user := models.User{
		FirstName:  "John",
		LastName:   "Doe",
		Email:      "john.doe@example.com",
		IsAdmin:    true,
		IsVerified: true,
		Password:   hash,
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

	accessToken := resp.Cookies()[0].Value
	refreshToken := resp.Cookies()[1].Value

	req2 := httptest.NewRequest("GET", "/api/users/profile", nil)
	req2.Header.Set("Content-Type", "application/json")

	req2.AddCookie(&http.Cookie{
		Name:  "accessToken", // Ensure this matches the cookie name used in your app
		Value: accessToken,
	})
	req2.AddCookie(&http.Cookie{
		Name:  "refreshToken", // Ensure this matches the cookie name used in your app
		Value: refreshToken,
	})

	resp2, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}

	// Verify that the response status code is 200 OK for successful login
	assert.Equal(t, http.StatusOK, resp2.StatusCode, "Expected status code 200 OK when get user profile")
}
