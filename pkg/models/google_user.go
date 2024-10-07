package models

type GoogleUser struct {
	Email          string `json:"email"`
	Family_name    string `json:"family_name"`
	Given_name     string `json:"given_name"`
	Id             string `json:"id"`
	Locale         string `json:"locale"`
	Name           string `json:"name"`
	Picture        string `json:"picture"`
	Verified_email bool   `json:"verified_email"`
}
