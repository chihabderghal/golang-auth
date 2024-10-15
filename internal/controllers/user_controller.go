package controllers

import (
	"errors"
	"fmt"
	"github.com/chihabderghal/user-service/config"
	"github.com/chihabderghal/user-service/internal/auth"
	"github.com/chihabderghal/user-service/pkg/models"
	"github.com/chihabderghal/user-service/pkg/utils"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"os"
	"time"
)

// GetAllUsers retrieves all users from the database.
// It returns a list of users in the response with a status of 200 (OK).
// If there is a database error, it responds with a 500 (Internal Server Error) and an error message.
func GetAllUsers(c *fiber.Ctx) error {
	// Fetch all users from the database
	var users []models.User
	if err := config.DB.Find(&users).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": err.Error(),
		})
	}

	// Respond with the list of users
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"users": users,
	})
}

// GetUserById retrieves the user based on the ID in the JWT token claims.
// It checks if the user is authenticated and returns the user's data.
// If unauthorized or if the user is not found, it returns an appropriate error response.
func GetUserById(c *fiber.Ctx) error {
	// Retrieve the access token from cookies
	token := c.Cookies("accessToken")
	if token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	// Parse the JWT token to get user claims
	claims, err := utils.ParseJwt(token, os.Getenv("AT_SECRET"))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized",
		})
	}

	// Fetch the user from the database using the ID from the token claims
	var user models.User
	err = config.DB.Where("id = ?", claims["sub"]).First(&user).Error
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "authentication failed: invalid email or password",
		})
	}

	// Respond with the user data
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"user": user,
	})
}

// GetAllAdminUsers retrieves all admin users from the database.
// It returns a list of users who have admin privileges in the response.
// If there is a database error, it responds with a 500 (Internal Server Error).
func GetAllAdminUsers(c *fiber.Ctx) error {
	// Fetch all admin users from the database
	var users []models.User
	if err := config.DB.Where("is_admin = true").Find(&users).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": err.Error(),
		})
	}

	// Respond with the list of admin users
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"users": users,
	})
}

// DeleteUserById deletes the user based on the ID in the JWT token claims.
// It ensures the user is authenticated and deletes the user from the database.
// If unauthorized or an error occurs during deletion, an appropriate error response is returned.
func DeleteUserById(c *fiber.Ctx) error {
	// Retrieve the access token from cookies
	token := c.Cookies("accessToken")
	if token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	// Parse the JWT token to get user claims
	claims, err := utils.ParseJwt(token, os.Getenv("AT_SECRET"))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized",
		})
	}

	// Fetch the user from the database using the ID from the token claims
	var user models.User
	err = config.DB.Where("id = ?", claims["sub"]).First(&user).Error
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Something went wrong",
		})
	}

	// Delete the user from the database
	if err := config.DB.Delete(&user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to delete user, try again later",
		})
	}

	// Return success response after deletion
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "User deleted successfully",
	})
}

// UpdateUser handles updating the authenticated user's profile information.
// The function allows users to optionally update their first name, last name, email, and profile picture.
// It also replaces the access and refresh tokens if the email is updated, and verifies the password for security purposes.
func UpdateUser(c *fiber.Ctx) error {
	// Retrieve the JWT token from cookies for authentication
	token := c.Cookies("accessToken")
	if token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	// Parse the JWT token to extract user claims
	claims, err := utils.ParseJwt(token, os.Getenv("AT_SECRET"))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	// Fetch the user from the database using the email from the JWT claims
	var user models.User
	err = config.DB.Where("email = ?", claims["email"]).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "User not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch user",
		})
	}

	// Structure to capture user update request data
	type UserUpdateBody struct {
		Firstname string `json:"firstName"`
		Lastname  string `json:"lastName"`
		Email     string `json:"email"`
		Picture   string `json:"picture"`
		Password  string `json:"password" validate:"required"`
	}

	// Ensure the uploads directory exists for saving profile pictures
	if _, err := os.Stat("./uploads"); os.IsNotExist(err) {
		err := os.Mkdir("./uploads", os.ModePerm)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Internal Server Error",
			})
		}
	}

	// Parse the incoming request body into the UserUpdateBody struct
	var input UserUpdateBody
	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid input",
		})
	}

	// validate user info
	if err := validate.Struct(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Password Required",
		})
	}

	// Optional updates: first name, last name, email, and password if they are provided
	if input.Firstname != "" {
		user.FirstName = input.Firstname
	}

	if input.Lastname != "" {
		user.LastName = input.Lastname
	}

	if input.Email != "" {
		// Check if the new email is already associated with another user
		var existingUser models.User
		if err := config.DB.Where("email = ?", input.Email).First(&existingUser).Error; err == nil && existingUser.ID != user.ID {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Email already taken",
			})
		}

		// Update user's email
		user.Email = input.Email
		// Update user's verified state
		user.IsVerified = false

		// Generate new access and refresh tokens with the new email claim
		tokens := auth.Tokens{
			AccessToken:  utils.GenerateAccessToken(user),
			RefreshToken: utils.GenerateRefreshToken(user),
		}

		// Update cookies with the new tokens
		c.Cookie(&fiber.Cookie{
			Name:     "accessToken",
			Value:    tokens.AccessToken,
			Expires:  time.Now().Add(time.Minute * 15),
			HTTPOnly: true,
			Secure:   false,
		})

		c.Cookie(&fiber.Cookie{
			Name:     "refreshToken",
			Value:    tokens.RefreshToken,
			Expires:  time.Now().Add(time.Hour * 24 * 7 * 4),
			HTTPOnly: true,
			Secure:   false,
		})
	}

	// Handle profile picture upload if provided
	file, err := c.FormFile("picture")
	if err == nil {
		// Save the uploaded profile picture
		imagePath := fmt.Sprintf("./uploads/%s-%s", time.Now().Format("20060102"), file.Filename)
		if err := c.SaveFile(file, imagePath); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Failed to save image",
			})
		}
		user.Picture = imagePath
	}

	// Verify that the provided password matches the stored one
	if !utils.CheckPasswordHash(input.Password, user.Password) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Password does not match",
		})
	}

	// Save updated user information to the database
	if err := config.DB.Save(&user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update user",
		})
	}

	// Return the updated user data, excluding sensitive fields like the password
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "User updated successfully",
	})
}
