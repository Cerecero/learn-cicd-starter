package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestApiKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		key     string
		error    error
	}{
		{
			name:    "No authorization Header",
			headers: http.Header{},
			key:     "",
			error:    ErrNoAuthHeaderIncluded,
		},
		{
			name: " Malformed Authorization Header - Missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"InvalidKey"},
			},
			key:  "",
			error: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header - Incorrect Format",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			key:  "",
			error: errors.New("malformed authorization header"),
		},
		{
			name: "Correct Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey 12345"},
			},
			key:  "12345",
			// error: nil,
			error: errors.New("malformed authorization header"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)
			if apiKey != tt.key {
				t.Errorf("expected API key %q, got %q", tt.key, apiKey)
			}
			if err != nil && tt.error == nil {
				t.Errorf("unexpected error: %v", err)
			} else if err == nil && tt.error != nil {
				t.Errorf("expected error %v, got nil", tt.error)
			} else if err != nil && tt.error != nil && err.Error() != tt.error.Error() {
				t.Errorf("expected error %v, got %v", tt.error, err)
			}
		})
	}
}

//
// var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")
//
// // GetAPIKey -
// func GetAPIKey(headers http.Header) (string, error) {
// 	authHeader := headers.Get("Authorization")
// 	if authHeader == "" {
// 		return "", ErrNoAuthHeaderIncluded
// 	}
// 	splitAuth := strings.Split(authHeader, " ")
// 	if len(splitAuth) < 2 || splitAuth[0] != "ApiKey" {
// 		return "", errors.New("malformed authorization header")
// 	}
//
// 	return splitAuth[1], nil
// }
