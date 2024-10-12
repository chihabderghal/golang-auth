package controllers

import (
	"errors"
	"fmt"
	"github.com/chihabderghal/user-service/config"
	"github.com/chihabderghal/user-service/internal/auth"
	"github.com/chihabderghal/user-service/pkg/models"
	"github.com/chihabderghal/user-service/pkg/utils"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"os"
	"time"
)

var validate = validator.New()

// Register handles user registration requests.
//
// @param c *fiber.Ctx: The Fiber context containing the request and response details.
//
// @returns error:
// - 400 Bad Request: Invalid request body or password hashing failure.
// - 409 Conflict: User already exists.
// - 201 Created: Registration successful with a success message in JSON format.
func Register(c *fiber.Ctx) error {
	// Get user info from body
	var userBody struct {
		Firstname string `json:"firstName" validate:"required"`
		Lastname  string `json:"lastName" validate:"required"`
		Email     string `json:"email" validate:"required,email"`
		Password  string `json:"password" validate:"required,min=8"`
	}

	if err := c.BodyParser(&userBody); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "invalid request body",
		})
	}

	// validate user info
	if err := validate.Struct(&userBody); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "invalid request body",
		})
	}

	// Check the user if already exists
	var existingUser models.User
	if err := config.DB.Where("email = ?", userBody.Email).First(&existingUser).Error; err == nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"message": "user already exists",
		})
	}

	// hash the password
	hash, err := utils.HashString(userBody.Password)
	if err != nil {
		c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "failed to hash password",
		})
	}

	// Create a User
	user := models.User{
		FirstName:  userBody.Firstname,
		LastName:   userBody.Lastname,
		Email:      userBody.Email,
		Password:   hash,
		IsVerified: false,
	}

	// Save user in db
	if err := config.DB.Create(&user).Error; err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "failed to create user",
		})
	}

	tokens := auth.Tokens{
		AccessToken:  utils.GenerateAccessToken(user),
		RefreshToken: utils.GenerateRefreshToken(user),
	}

	// Set Access Token in the Cookie
	c.Cookie(&fiber.Cookie{
		Name:     "accessToken",
		Value:    tokens.AccessToken,
		Expires:  time.Now().Add(time.Minute * 15),
		HTTPOnly: true,
		Secure:   false,
	})

	// Set Refresh Token in the Cookie
	c.Cookie(&fiber.Cookie{
		Name:     "refreshToken",
		Value:    tokens.RefreshToken,
		Expires:  time.Now().Add(time.Hour * 24 * 7 * 4),
		HTTPOnly: true,
		Secure:   false,
	})

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "Register successful",
	})
}

// Login handles user login requests.
//
// @param c *fiber.Ctx: The Fiber context containing the request and response details.
//
// @returns error:
// - 400 Bad Request: Invalid request body.
// - 401 Unauthorized: Authentication failed due to invalid email or password.
// - 200 OK: Login successful with a success message in JSON format.
func Login(c *fiber.Ctx) error {
	// Get credentials
	var userBody struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required,min=8"`
	}

	if err := c.BodyParser(&userBody); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "invalid request body",
		})
	}

	// validate user info
	if err := validate.Struct(&userBody); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "invalid request body",
		})
	}

	// Check if the user exists
	var user models.User
	err := config.DB.Where("email = ?", userBody.Email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "authentication failed: invalid email or password",
			})
		}
		return nil
	}

	// Compare the given password with the hash
	if !utils.CheckPasswordHash(userBody.Password, user.Password) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "authentication failed: invalid email or password",
		})
	}

	// Create tokens
	tokens := auth.Tokens{
		AccessToken:  utils.GenerateAccessToken(user),
		RefreshToken: utils.GenerateRefreshToken(user),
	}

	// Set Access Token in the Cookie
	c.Cookie(&fiber.Cookie{
		Name:     "accessToken",
		Value:    tokens.AccessToken,
		Expires:  time.Now().Add(time.Minute * 15),
		HTTPOnly: true,
		Secure:   false,
	})

	// Set Refresh Token in the Cookie
	c.Cookie(&fiber.Cookie{
		Name:     "refreshToken",
		Value:    tokens.RefreshToken,
		Expires:  time.Now().Add(time.Hour * 24 * 7 * 4),
		HTTPOnly: true,
		Secure:   false,
	})

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Login successful",
	})
}

// VerifyEmail handles email verification requests using a token.
//
// @param c *fiber.Ctx: The Fiber context containing the request and response details.
//
// @returns error:
// - 400 Bad Request: Invalid or expired verification token.
// - 401 Unauthorized: Verification token has expired or user not found.
// - 200 OK: Email successfully verified with a success message in JSON format.
func VerifyEmail(c *fiber.Ctx) error {
	// Get the token from the query parameters
	token := c.Query("token")

	// Find the token record by the verification token
	var verificationToken models.VerificationToken
	if err := config.DB.Where("token = ?", token).First(&verificationToken).Error; err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid or expired verification token",
		})
	}

	// Check if the token has expired
	if time.Now().After(verificationToken.ExpiredAt) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Verification token has expired",
		})
	}

	// Find the associated user
	var user models.User
	if err := config.DB.Where("id = ?", verificationToken.UserId).First(&user).Error; err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "User not found",
		})
	}

	// Check if the user is already verified
	if user.IsVerified {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "User is already verified",
		})
	}

	// Update the user's verification status
	user.IsVerified = true
	if err := config.DB.Save(&user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to verify user",
		})
	}

	// Delete or deactivate the verification token after use
	if err := config.DB.Unscoped().Delete(&verificationToken).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to clean up verification token",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Email successfully verified",
	})
}

// SendEmailVerification sends an email verification link to the user.
//
// @param c *fiber.Ctx: The Fiber context containing the request and response details.
//
// @returns error:
// - 400 Bad Request: Token claims could not be parsed, or user ID is invalid.
// - 401 Unauthorized: Missing or invalid access token.
// - 404 Not Found: The user associated with the token is not found in the database.
// - 500 Internal Server Error: Failed to create the verification token or send the verification email.
// - 200 OK: Email sent successfully with a verification link.
func SendEmailVerification(c *fiber.Ctx) error {
	// Retrieve the access token from cookies
	cookie := c.Cookies("accessToken")
	if cookie == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Missing access token",
		})
	}

	// Parse the JWT token from the cookie using the provided secret
	claims, err := utils.ParseJwt(cookie, os.Getenv("AT_SECRET"))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to parse JWT token",
		})
	}

	// Retrieve user ID from the token claims
	userId, ok := claims["sub"]
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid user ID in token",
		})
	}

	// Find the associated user in the database
	var user models.User
	if err := config.DB.Where("id = ?", userId).First(&user).Error; err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "User not found",
		})
	}

	// Create a verification token for the user
	verificationToken := models.VerificationToken{
		Token:     uuid.New(),
		ExpiredAt: time.Now().Add(time.Minute * 15), // 15 minutes
		UserId:    user.ID,
	}

	// Save VerificationToken on DB
	if err := config.DB.Create(&verificationToken).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "failed to create verification token",
		})
	}

	// Generate the email verification link and the corresponding email body content.
	// The link directs the user to verify their email using the provided token.
	verificationLink := fmt.Sprintf("http://localhost:5000/api/auth/verify?token=%s", verificationToken.Token)
	emailBody := fmt.Sprintf("<p>Please verify your email by clicking the following link: <a href=\"%s\">Verify Email</a></p>", verificationLink)

	// Define the subject line for the email.
	subject := "Email Verification"

	// After generating the verification token
	err = utils.SendVerificationEmail(user.Email, emailBody, subject)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Please check your inbox to verify your email address.",
	})
}

// ForgotPassword handles the request to send a password reset link to the user's email.
//
// @param c *fiber.Ctx: The Fiber context containing the request and response details.
//
// @returns error:
// - 400 Bad Request: Invalid email format or email not found in the database.
// - 500 Internal Server Error: Failed to create the verification token or send the password reset email.
// - 200 OK: Email sent successfully with a password reset link.
func ForgotPassword(c *fiber.Ctx) error {
	// Parse the user's email from the request body
	var userBody struct {
		Email string `json:"email" validate:"required,email"`
	}

	if err := c.BodyParser(&userBody); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid request body",
		})
	}

	// Validate the email field to ensure it's properly formatted
	if err := validate.Struct(&userBody); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid email format",
		})
	}

	// Check if a user with the given email exists in the database
	var user models.User
	if err := config.DB.Where("email = ?", userBody.Email).First(&user).Error; err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Email not found",
		})
	}

	// Create a new password reset token for the user
	verificationToken := models.VerificationToken{
		Token:     uuid.New(),
		ExpiredAt: time.Now().Add(time.Minute * 15), // Token is valid for 15 minutes
		UserId:    user.ID,
	}

	// Store the generated verification token in the database
	if err := config.DB.Create(&verificationToken).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to create verification token",
		})
	}

	// Generate the password reset link using the verification token
	// Create the email body for the password reset request
	resetLink := fmt.Sprintf("http://localhost:5000/api/auth/reset-password?token=%s", verificationToken.Token)
	emailBody := fmt.Sprintf("<p>You requested to reset your password. Please click the following link to reset it: <a href=\"%s\">Reset Password</a></p>", resetLink)

	// Define the subject line for the email.
	subject := "Password Reset Request"

	// After generating the verification token
	err := utils.SendVerificationEmail(user.Email, emailBody, subject)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": err.Error(),
		})
	}

	// Return a success message indicating that the password reset email was sent
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Check your inbox for the password reset link.",
	})
}

// ResetPassword handles the request to reset a user's password using a verification token.
//
// @param c *fiber.Ctx: The Fiber context containing the request and response details.
//
// @returns error:
// - 400 Bad Request: Invalid or expired verification token, or invalid request body.
// - 500 Internal Server Error: Failed to hash the new password or reset the password in the database.
// - 200 OK: Password reset successfully.
func ResetPassword(c *fiber.Ctx) error {
	// Retrieve the verification token from the query parameters
	token := c.Query("token")

	// Look up the verification token in the database
	var verificationToken models.VerificationToken
	if err := config.DB.Where("token = ?", token).First(&verificationToken).Error; err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid or expired verification token",
		})
	}

	// Check if the verification token has expired
	if time.Now().After(verificationToken.ExpiredAt) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Verification token has expired",
		})
	}

	// Retrieve the user associated with the token from the database
	var user models.User
	if err := config.DB.Where("id = ?", verificationToken.UserId).First(&user).Error; err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "User not found",
		})
	}

	// Parse the new password from the request body
	var userBody struct {
		Password string `json:"password" validate:"required,min=8"`
	}

	if err := c.BodyParser(&userBody); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid request body",
		})
	}

	// Validate the password input
	if err := validate.Struct(&userBody); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid password",
		})
	}

	// hash the password
	hash, err := utils.HashString(userBody.Password)
	if err != nil {
		c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "failed to hash password",
		})
	}

	// Update the user's password in the database
	user.Password = hash

	if err := config.DB.Save(&user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to reset password",
		})
	}

	// Remove the verification token after it has been used
	if err := config.DB.Unscoped().Delete(&verificationToken).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to remove verification token",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Password successfully reset",
	})
}
