/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestKeycloakGroupSyncFunctional tests actual Keycloak group retrieval.
// Test ID: GSYNC-001 (Medium)
func TestKeycloakGroupSyncFunctional(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	if !helpers.IsKeycloakTestEnabled() {
		t.Skip("Keycloak tests disabled")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	keycloakURL := helpers.GetKeycloakURL()
	realm := helpers.GetKeycloakRealm()
	clientID := helpers.GetKeycloakServiceAccountClientID()
	clientSecret := helpers.GetKeycloakServiceAccountSecret()

	t.Logf("Keycloak URL: %s, Realm: %s", keycloakURL, realm)

	token, err := getKeycloakToken(ctx, keycloakURL, realm, clientID, clientSecret)
	if err != nil {
		t.Skipf("Could not get Keycloak token: %v", err)
	}

	testUserEmail := helpers.GetTestUserEmail()
	userID, err := getKeycloakUser(ctx, keycloakURL, realm, token, testUserEmail)
	if err != nil {
		t.Skipf("Could not find test user: %v", err)
	}

	groups, err := getKeycloakGroups(ctx, keycloakURL, realm, token, userID)
	require.NoError(t, err, "Should fetch user groups")
	t.Logf("User groups: %v", groups)
	assert.NotNil(t, groups)

	t.Run("GroupLookupPerformance", func(t *testing.T) {
		start := time.Now()
		_, err := getKeycloakGroups(ctx, keycloakURL, realm, token, userID)
		require.NoError(t, err)
		assert.Less(t, time.Since(start), 5*time.Second)
	})
}

func getKeycloakToken(ctx context.Context, baseURL, realm, clientID, clientSecret string) (string, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", baseURL, realm)
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // E2E test uses self-signed certs
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed: %d - %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	return tokenResp.AccessToken, nil
}

func getKeycloakUser(ctx context.Context, baseURL, realm, token, email string) (string, error) {
	usersURL := fmt.Sprintf("%s/admin/realms/%s/users?email=%s&exact=true", baseURL, realm, url.QueryEscape(email))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, usersURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // E2E test uses self-signed certs
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("users request failed: %d - %s", resp.StatusCode, string(body))
	}

	var users []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return "", err
	}
	if len(users) == 0 {
		return "", fmt.Errorf("user not found: %s", email)
	}
	return users[0].ID, nil
}

func getKeycloakGroups(ctx context.Context, baseURL, realm, token, userID string) ([]string, error) {
	groupsURL := fmt.Sprintf("%s/admin/realms/%s/users/%s/groups", baseURL, realm, userID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, groupsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // E2E test uses self-signed certs
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("groups request failed: %d - %s", resp.StatusCode, string(body))
	}

	var groups []struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&groups); err != nil {
		return nil, err
	}

	result := make([]string, 0, len(groups))
	for _, g := range groups {
		if g.Path != "" {
			result = append(result, g.Path)
		} else {
			result = append(result, g.Name)
		}
	}
	return result, nil
}
