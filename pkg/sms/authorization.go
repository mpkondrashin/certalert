package sms

import "net/http"

// Authorization - Interface for SMS authorisation
type Authorization interface {
	Auth(request *http.Request)
}

// UserPasswordAuthorization - SMS authorization using username and password
type UserPasswordAuthorization struct {
	name     string
	password string
}

// NewUserPasswordAuthorization - return username and password authorization
func NewUserPasswordAuthorization(name, password string) *UserPasswordAuthorization {
	return &UserPasswordAuthorization{
		name:     name,
		password: password,
	}
}

// Auth - add basic auth headers to the request
func (a *UserPasswordAuthorization) Auth(request *http.Request) {
	request.SetBasicAuth(a.name, a.password)
}

// APIKeyAuthorization - SMS authorization using API key
type APIKeyAuthorization struct {
	apiKey string
}

// NewAPIKeyAuthorization - return authorization using API key
func NewAPIKeyAuthorization(apiKey string) *APIKeyAuthorization {
	return &APIKeyAuthorization{
		apiKey: apiKey,
	}
}

// Auth - add APY key header to the request
func (a *APIKeyAuthorization) Auth(request *http.Request) {
	request.Header.Add("X-SMS-API-KEY", a.apiKey)
}
