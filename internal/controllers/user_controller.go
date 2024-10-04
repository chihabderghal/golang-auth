package controllers

import (
	"errors"
	"github.com/chihabderghal/user-service/internal/auth"
	"github.com/chihabderghal/user-service/internal/config"
	"github.com/chihabderghal/user-service/pkg/models"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserRegister struct {
	Firstname  string `json:"firstName" validate:"required"`
	Lastname   string `json:"lastName" validate:"required"`
	Country    string `json:"country" validate:"required"`
	Email      string `json:"email" validate:"required,email"`
	Password   string `json:"password" validate:"required,min=8"`
	IsVerified bool   `json:"isVerified"`
}

type UserLogin struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

var validate = validator.New()

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

	var existingUser models.User
	if err := config.DB.Where("email = ?", userBody.Email).First(&existingUser).Error; err == nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"message": "user already exists",
		})
	}

	// hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(userBody.Password), bcrypt.DefaultCost)
	if err != nil {
		c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "failed to hash password",
		})
	}

	// save user in db
	user := models.User{
		FirstName: userBody.Firstname,
		LastName:  userBody.Lastname,
		Country:   userBody.Country,
		Email:     userBody.Email,
		Password:  string(hash),
	}

	creation := config.DB.Create(&user)
	if creation.Error != nil {
		c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "failed to create user",
		})
	}

	tokens := auth.Tokens{
		AccessToken:  auth.GenerateAccessToken(user),
		RefreshToken: auth.GenerateRefreshToken(user),
	}

	return c.Status(fiber.StatusCreated).JSON(
		tokens,
	)
}

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

	// Return tokens
	return c.Status(fiber.StatusOK).JSON(
		tokens,
	)
}

func Refresh(c *fiber.Ctx) error {
	return nil
}
