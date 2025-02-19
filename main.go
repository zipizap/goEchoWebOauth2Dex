package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc" // OIDC library
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/oauth2"
)

/*
Configuration for your Dex and client.
Adjust these values according to your Dex configuration.

DEX: (aka issuer)

		http://127.0.0.1:5556/dex
	    - connector: mockCallback
		or
		- email/pass: admin@example.com // password

App: (aka client)

		CLIENT_ID: example-app
		CLIENT_SECRET: ZXhhbXBsZS1hcHAtc2VjcmV0
	    REDIRECT_URL: http://127.0.0.1:5555/callback
		homepage:     http://127.0.0.1:5555
*/
var (
	clientID     = "example-app"
	clientSecret = "ZXhhbXBsZS1hcHAtc2VjcmV0"
	// Dex issuer URL (typically something like "http://127.0.0.1:5556/dex")
	issuer      = "http://127.0.0.1:5556/dex"
	redirectURL = "http://127.0.0.1:5555/callback"

	// Global variables for OAuth2 and OIDC verification.
	oauth2Config *oauth2.Config
	oidcProvider *oidc.Provider
	oidcVerifier *oidc.IDTokenVerifier
)

// randomState generates a random string used to validate the OAuth2 flow.
func randomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func main() {
	// Initialize OIDC provider from Dex.
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatalf("Failed to initialize OIDC provider: %v", err)
	}
	oidcProvider = provider

	// Configure OAuth2 with OIDC scopes.
	oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	// Create an ID Token verifier to verify tokens received from Dex.
	oidcVerifier = provider.Verifier(&oidc.Config{ClientID: clientID})

	// Create a new Echo instance.
	e := echo.New()

	// Use logging and recovery middleware.
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Add index route.
	e.GET("/", indexHandler)

	// Public route: accessible by anyone.
	e.GET("/public", func(c echo.Context) error {
		return c.HTML(http.StatusOK, `<html>
			<body>
				<h1>Public Page</h1>
				<p>This is a public page.</p>
				<ul>
					<li><a href="/public">Public</a></li>
					<li><a href="/login">Login</a></li>
					<li><a href="/logout">Logout</a></li>
					<li><a href="/private">Private</a></li>
				</ul>
				</p><hr></p>
			</body>
		</html>`)
	})

	// Start the login process.
	e.GET("/login", loginHandler)

	// Callback URL for the OIDC flow.
	e.GET("/callback", callbackHandler)

	// Private route: requires a valid ID token.
	e.GET("/private", privateHandler, authMiddleware)

	// Logout route: clears the ID token.
	e.GET("/logout", logoutHandler)

	// Start the server.
	e.Logger.Fatal(e.Start(":5555"))
}

// loginHandler initiates the OAuth2 login process by generating a state value,
// saving it in a cookie, and redirecting the user to Dex’s login page.
func loginHandler(c echo.Context) error {
	// Generate a random state string.
	state, err := randomState()
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
	c.SetCookie(stateCookie)

	// Redirect the user to Dex’s authorization endpoint.
	authURL := oauth2Config.AuthCodeURL(state)
	return c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// callbackHandler handles the OAuth2 callback from Dex. It verifies the state,
// exchanges the authorization code for an ID token, verifies the ID token, and then
// stores the ID token as cookie "id_token" for later authentication.
func callbackHandler(c echo.Context) error {
	ctx := context.Background()

	// Retrieve state and code from query parameters.
	state := c.QueryParam("state")
	code := c.QueryParam("code")

	// Retrieve the state we stored earlier.
	stateCookie, err := c.Cookie("oauthstate")
	if err != nil {
		return c.String(http.StatusBadRequest, "State cookie not found")
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
	idToken, err := oidcVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to verify ID Token: %v", err))
	}

	// Optionally, you can decode token claims.
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to parse claims: %v", err))
	}
	log.Printf("User claims: %v", claims)

	// Save the raw ID token in a cookie to maintain the session.
	tokenCookie := &http.Cookie{
		Name:     "id_token",
		Value:    rawIDToken,
		Path:     "/",
		HttpOnly: true, // Block JS access to cookie
	}
	c.SetCookie(tokenCookie)

	// Redirect the user to the private page.
	return c.Redirect(http.StatusTemporaryRedirect, "/private")
}

// authMiddleware is a custom middleware that checks for a valid ID token
// in the cookies. If not found or invalid, the user is redirected to /login.
func authMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Retrieve the ID token from the cookie.
		cookie, err := c.Cookie("id_token")
		if err != nil {
			return c.Redirect(http.StatusTemporaryRedirect, "/login")
		}
		rawIDToken := cookie.Value

		// Verify the ID token.
		ctx := context.Background()
		_, err = oidcVerifier.Verify(ctx, rawIDToken)
		if err != nil {
			// If verification fails, force a login.
			return c.Redirect(http.StatusTemporaryRedirect, "/login")
		}
		// Token is valid; proceed to the handler.
		return next(c)
	}
}

// privateHandler serves the private page, which is only accessible
// if the user is authenticated via Dex.
func privateHandler(c echo.Context) error {
	cookie, err := c.Cookie("id_token")
	if err != nil {
		return c.String(http.StatusUnauthorized, "Missing ID token")
	}

	idToken, err := oidcVerifier.Verify(context.Background(), cookie.Value)
	if err != nil {
		return c.String(http.StatusUnauthorized, "Invalid ID token")
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to parse claims: %v", err))
	}

	return c.HTML(http.StatusOK, fmt.Sprintf(`<html>
		<body>
			<h1>Private</h1>
			<p>Private access granted</p>
			<p>ID_Token: %s</p>
			<p>Claims: %v</p>
			<ul>
				<li><a href="/public">Public</a></li>
				<li><a href="/login">Login</a></li>
				<li><a href="/logout">Logout</a></li>
				<li><a href="/private">Private</a></li>
			</ul>
			</p><hr></p>
		</body>
	</html>`, cookie.Value, claims))
}

// logoutHandler clears the ID token cookie and redirects the user to the public page.
func logoutHandler(c echo.Context) error {
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
	return c.Redirect(http.StatusTemporaryRedirect, "/public")
}

func indexHandler(c echo.Context) error {
	html := `<html>
		<body>
			<h1>Index</h1>
			<ul>
				<li><a href="/public">Public</a></li>
				<li><a href="/login">Login</a></li>
				<li><a href="/logout">Logout</a></li>
				<li><a href="/private">Private</a></li>
			</ul>
			</p><hr></p>
		</body>
	</html>`
	return c.HTML(http.StatusOK, html)
}
