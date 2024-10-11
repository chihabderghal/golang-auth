package utils

import (
	"fmt"
	"github.com/resend/resend-go/v2"
	"os"
)

func SendVerificationEmail(userEmail string, subject string, emailBody string) error {
	// Retrieve the Resend API key.
	apikey := os.Getenv("RESEND_API_KEY")
	// Create a Resend client.
	client := resend.NewClient(apikey)

	// Prepare the email parameters.
	params := &resend.SendEmailRequest{
		From:    "Chihab Derghal <golang@resend.dev>",
		To:      []string{userEmail},
		Html:    emailBody,
		Subject: subject,
	}

	// Send the email to the user for verification.
	_, err := client.Emails.Send(params)
	if err != nil {
		return fmt.Errorf("failed to send verification email: %v", err)
	}

	return nil
}
