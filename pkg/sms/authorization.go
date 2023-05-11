package sms

import "net/http"

type Autherization interface {
	Auth(request *http.Request)
}

type UserPasswordAuthorization struct {
	name     string
	password string
}

func NewUserPasswordAuthorization(name, password string) *UserPasswordAuthorization {
	return &UserPasswordAuthorization{
		name:     name,
		password: password,
	}
}

func (a *UserPasswordAuthorization) Auth(request *http.Request) {
	request.SetBasicAuth(a.name, a.password)
}

type APIKeyAuthorization struct {
	apiKey string
}

func NewAPIKeyAuthorization(apiKey string) *APIKeyAuthorization {
	return &APIKeyAuthorization{
		apiKey: apiKey,
	}
}

func (a *APIKeyAuthorization) Auth(request *http.Request) {
	request.Header.Add("X-SMS-API-KEY", a.apiKey)
}
