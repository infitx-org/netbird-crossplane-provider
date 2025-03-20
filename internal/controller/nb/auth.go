package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Scope        string `json:"scope"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func GetTokenUsingOauth(oauthCredentialsConfig string, issuerUrlString string) (string, error) {
	var token string
	var tokenRequest TokenRequest
	err := json.Unmarshal([]byte(oauthCredentialsConfig), &tokenRequest)
	if err != nil {
		return "", err
	}
	formBody := url.Values{}
	formBody.Set("client_id", tokenRequest.ClientID)
	formBody.Set("client_secret", tokenRequest.ClientSecret)
	formBody.Set("grant_type", tokenRequest.GrantType)
	formBody.Set("scope", tokenRequest.Scope)
	req, err := http.NewRequest(http.MethodPost, issuerUrlString, strings.NewReader(formBody.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	httpClient := http.Client{}

	res, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	var tokenResponse TokenResponse
	err = json.Unmarshal(respBody, &tokenResponse)
	if err != nil {
		return "", err
	}
	token = tokenResponse.AccessToken
	return token, err
}
