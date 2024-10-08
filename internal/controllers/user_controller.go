package controllers

import (
	"errors"
	"fmt"
	"github.com/chihabderghal/user-service/internal/auth"
	"github.com/chihabderghal/user-service/internal/config"
	"github.com/chihabderghal/user-service/pkg/models"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/resend/resend-go/v2"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"os"
	"time"
)

type UserRegister struct {
	Firstname string `json:"firstName" validate:"required"`
	Lastname  string `json:"lastName" validate:"required"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	Picture   string `json:"picture"`
}

type UserLogin struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

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
	var userBody UserRegister
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

	if _, err := os.Stat("./uploads"); os.IsNotExist(err) {
		err := os.Mkdir("./uploads", os.ModePerm)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Internal Server Error",
			})
		}
	}

	file, err := c.FormFile("image")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "failed to upload image",
		})
	}

	imagePath := fmt.Sprintf("./uploads/%s-%s", time.Now().Format("20060102"), file.Filename)

	if err := c.SaveFile(file, imagePath); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "failed to save image",
		})
	}

	// hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(userBody.Password), bcrypt.DefaultCost)
	if err != nil {
		c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "failed to hash password",
		})
	}

	// Email verification token
	verificationToken := uuid.New().String()

	// save user in db
	user := models.User{
		FirstName:         userBody.Firstname,
		LastName:          userBody.Lastname,
		Email:             userBody.Email,
		Password:          string(hash),
		Picture:           imagePath,
		IsVerified:        false,
		VerificationToken: verificationToken,
	}

	creation := config.DB.Create(&user)
	if creation.Error != nil {
		c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "failed to create user",
		})
	}

	// TODO: Email verification
	apikey := os.Getenv("RESEND_API_KEY")

	client := resend.NewClient(apikey)
	verificationLink := fmt.Sprintf("http://localhost:5000/api/auth/verify?token=%s", verificationToken)
	body := fmt.Sprintf("<p>Please verify your email by clicking the following link: <a href=\"%s\">Verify Email</a></p>", verificationLink)

	params := &resend.SendEmailRequest{
		From:    "Chihab Derghal <golang@resend.dev>",
		To:      []string{userBody.Email},
		Html:    body,
		Subject: "Email verification",
	}

	_, err = client.Emails.Send(params)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "failed to send verification email",
		})
	}

	tokens := auth.Tokens{
		AccessToken:  auth.GenerateAccessToken(user),
		RefreshToken: auth.GenerateRefreshToken(user),
	}

	// Set Access Token in the Cookie
	c.Cookie(&fiber.Cookie{
		Name:     "access_token",
		Value:    tokens.AccessToken,
		Expires:  time.Now().Add(time.Minute * 15),
		HTTPOnly: true,
		Secure:   false,
	})

	// Set Refresh Token in the Cookie
	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    tokens.RefreshToken,
		Expires:  time.Now().Add(time.Hour * 24 * 7 * 4),
		HTTPOnly: true,
		Secure:   false,
	})

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "Register successful",
	})
}

func VerifyEmail(c *fiber.Ctx) error {
	// Get token from query params
	token := c.Query("token")
	if token == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "invalid token",
		})
	}

	// Find user by token
	var user models.User
	if err := config.DB.Where("verification_token = ?", token).First(&user).Error; err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "invalid or expired token",
		})
	}

	// Verify the user
	user.IsVerified = true
	// Clear the token
	user.VerificationToken = ""

	config.DB.Save(&user)

	if err := config.DB.Save(&user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "failed to verify email",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Email verified successfully",
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
	var userBody UserLogin
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

	// Create tokens
	tokens := auth.Tokens{
		AccessToken:  auth.GenerateAccessToken(user),
		RefreshToken: auth.GenerateRefreshToken(user),
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
