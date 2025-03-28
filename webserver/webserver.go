package webserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url" // added for URL escaping

	"github.com/coreos/go-oidc/v3/oidc" // OIDC library
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

var (
	configOauthClientDex *ConfigOauthClientDex
	oauth2Config         *oauth2.Config
	OidcVerifier         *oidc.IDTokenVerifier

	E = echo.New()
)

type ConfigOauthClientDex struct {
	ClientID          string
	ClientSecret      string
	ClientRedirectURL string
	ClientScopes      []string
	DexIssuer         string
}

// oauthRandomState generates a random string used to validate the OAuth2 flow.
func oauthRandomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func oauthInitOidcProviderFromDex() error {
	// Initialize OIDC provider from Dex.
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, configOauthClientDex.DexIssuer)
	if err != nil {
		return fmt.Errorf("failed to initialize OIDC provider: %v", err)
	}

	// Configure OAuth2 with OIDC scopes.
	oauth2Config = &oauth2.Config{
		ClientID:     configOauthClientDex.ClientID,
		ClientSecret: configOauthClientDex.ClientSecret,
		RedirectURL:  configOauthClientDex.ClientRedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       configOauthClientDex.ClientScopes,
	}

	// Create an ID Token verifier to verify tokens received from Dex.
	OidcVerifier = provider.Verifier(&oidc.Config{ClientID: configOauthClientDex.ClientID})
	return nil

}

// Start() - setup Oidc and starts server:
// - setup Oidc on paths /login, /callback, /logout
//
//	and start the server.
func Start(webserverConfigOauth *ConfigOauthClientDex) {
	configOauthClientDex = webserverConfigOauth
	oauthInitOidcProviderFromDex()

	// Oauth handlers: /login, /callback, /logout
	// Start the login process.
	E.GET("/login", oauthLoginHandler)

	// Callback URL for the OIDC flow.
	E.GET("/callback", oauthCallbackHandler)

	// Logout route: clears the ID token.
	E.GET("/logout", oauthLogoutHandler)

	// Start the server.
	E.Logger.Fatal(E.Start(":8080"))
}

// oauthLoginHandler initiates the OAuth2 login process by generating a state value,
// saving it in a cookie, and redirecting the user to Dex’s login page.
func oauthLoginHandler(c echo.Context) error {
	// Capture the original protected URL if provided.
	redirectURL := c.QueryParam("redirect")
	if redirectURL != "" {
		redirectCookie := &http.Cookie{
			Name:     "redirect_url",
			Value:    redirectURL,
			Path:     "/",
			HttpOnly: true,
		}
		c.SetCookie(redirectCookie)
	}

	// Generate a random state string.
	state, err := oauthRandomState()
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error generating state")
	}

	// Save the state in a cookie so we can verify it later.
	stateCookie := &http.Cookie{
		Name:     "oauthstate",
		Value:    state,
		Path:     "/",
		HttpOnly: true,    // Block JS access to cookie
		MaxAge:   15 * 60, // 15 minutes in seconds, for the oauth2 login to complete
	}
	stateCookie.SameSite = http.SameSiteLaxMode // Specify SameSite attribute
	c.SetCookie(stateCookie)

	// Redirect the user to Dex’s authorization endpoint.
	authURL := oauth2Config.AuthCodeURL(state)
	return c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// oauthCallbackHandler handles the OAuth2 callback from Dex. It verifies the state,
// exchanges the authorization code for an ID token, verifies the ID token, and then
// stores the ID token as cookie "id_token" for later authentication.
func oauthCallbackHandler(c echo.Context) error {
	ctx := context.Background()

	// Retrieve state and code from query parameters.
	state := c.QueryParam("state")
	code := c.QueryParam("code")

	// Retrieve the state we stored earlier.
	stateCookie, err := c.Cookie("oauthstate")
	if err != nil {
		return c.String(http.StatusBadRequest, fmt.Sprintf("State cookie not found  - %s", err))
	}
	if state != stateCookie.Value {
		return c.String(http.StatusBadRequest, "Invalid state parameter")
	}

	// Exchange the authorization code for an OAuth2 token.
	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Token exchange failed: %v", err))
	}

	// Extract the raw ID token from the token response.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return c.String(http.StatusInternalServerError, "No id_token field in token response")
	}

	// Verify the ID token.
	idToken, err := OidcVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to verify ID Token: %v", err))
	}

	// Optionally, you can decode token claims.
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to parse claims: %v", err))
	}
	// log.Printf("User claims: %v", claims)

	// Save the raw ID token in a cookie to maintain the session.
	tokenCookie := &http.Cookie{
		Name:     "id_token",
		Value:    rawIDToken,
		Path:     "/",
		HttpOnly: true, // Block JS access to cookie
	}
	c.SetCookie(tokenCookie)

	// Check for a redirect cookie.
	target := "/"
	if redirectCookie, err := c.Cookie("redirect_url"); err == nil {
		target = redirectCookie.Value
		// Clear the redirect cookie.
		clearCookie := &http.Cookie{
			Name:     "redirect_url",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		}
		c.SetCookie(clearCookie)
	}

	// Redirect the user to the private page.
	return c.Redirect(http.StatusTemporaryRedirect, target)
}

// OauthIdTokenValidatorMiddleware is a custom middleware that checks for a valid ID token
// in the cookies. If not found or invalid, the user is redirected to /login.
// Should be used to protect requests for HTML pages.
// To protect API endpoints, use instead OauthIdTokenValidatorApiMiddleware.
func OauthIdTokenValidatorMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Retrieve the ID token from the cookie.
		cookie, err := c.Cookie("id_token")
		if err != nil {
			// Redirect to /login with original path as query parameter.
			redirectTo := url.QueryEscape(c.Request().RequestURI)
			return c.Redirect(http.StatusTemporaryRedirect, "/login?redirect="+redirectTo)
		}
		rawIDToken := cookie.Value

		// Verify the ID token.
		ctx := context.Background()
		idToken, err := OidcVerifier.Verify(ctx, rawIDToken)
		if err != nil {
			// If verification fails, force a login.
			// Redirect to /login with original path as query parameter.
			redirectTo := url.QueryEscape(c.Request().RequestURI)
			return c.Redirect(http.StatusTemporaryRedirect, "/login?redirect="+redirectTo)
		}

		// Parse the idTokenClaims
		var idTokenClaims map[string]interface{}
		if err := idToken.Claims(&idTokenClaims); err != nil {
			// If claims parsing fails, set claims to nil.
			idTokenClaims = nil
		}
		c.Set("idTokenClaims", idTokenClaims) // store the token in the context

		// Continue to the handler.
		return next(c)
	}
}

// OauthIdTokenValidatorApiMiddleware is a custom middleware that checks for a valid ID token
// in the cookies. If not found or invalid, the reply is a 401 Unauthorized with json-body {"error": "Login required"}.
// Should be used to protect API endpoints.
// To protect HTML pages, use instead OauthIdTokenValidatorMiddleware.
func OauthIdTokenValidatorApiMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Retrieve the ID token from the cookie.
		cookie, err := c.Cookie("id_token")
		if err != nil {
			// Verification failed - return 401 Unauthorized with json body containing error.
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Login required"})
		}

		// Verify the ID token.
		idToken, err := OidcVerifier.Verify(context.Background(), cookie.Value)
		if err != nil {
			// Verification failed - return 401 Unauthorized with json body containing error.
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Login required"})
		}

		// Parse the idTokenClaims
		var idTokenClaims map[string]interface{}
		if err := idToken.Claims(&idTokenClaims); err != nil {
			// If claims parsing fails, set claims to nil.
			idTokenClaims = nil
		}
		c.Set("idTokenClaims", idTokenClaims) // store the token in the context

		// Continue to the next handler
		return next(c)
	}
}

// oauthLogoutHandler clears the ID token cookie and redirects the user to the public page.
func oauthLogoutHandler(c echo.Context) error {
	// Clear the ID token cookie.
	cookie := &http.Cookie{
		Name:     "id_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true, // Block JS access to cookie
	}
	c.SetCookie(cookie)
	// Redirect user.
	return c.Redirect(http.StatusTemporaryRedirect, "/")
}
