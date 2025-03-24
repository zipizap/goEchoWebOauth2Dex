/*
Package webserver provides a simple web server with OAuth 2.0 authentication using Dex.

The package offers the following features:

- Configuration via ConfigOauthClientDex to specify OAuth 2.0 client details and Dex issuer information.
- Initialization of the OIDC provider and OAuth 2.0 configuration.
- Handlers for login, callback, and logout to manage the OAuth 2.0 flow.
- Middleware for validating ID tokens to protect routes.

Usage:

1.  Create a ConfigOauthClientDex struct with the necessary configuration details:

	config := &webserver.ConfigOauthClientDex{
		ClientID:          "example-app",
		ClientSecret:      "ZXhhbXBsZS1hcHAtc2VjcmV0",
		ClientRedirectURL: "http://127.0.0.1:8080/callback",
		ClientScopes:      []string{"openid", "profile", "email", "groups"},
		DexIssuer:         "http://127.0.0.1:5556/dex",
	}

2.  Define middleware and routes. Protect routes using the OauthIdTokenValidatorMiddleware or OauthIdTokenValidatorApiMiddleware middleware:

	OauthIdTokenValidatorMiddleware will:
	- Check for a valid ID token in the "id_token" cookie.
	- If the token is missing or invalid, redirect the user to the /login page.

	OauthIdTokenValidatorApiMiddleware will:
	- Check for a valid ID token in the "id_token" cookie.
	- If the token is missing or invalid, return a 401 Unauthorized with json-body {"error": "Login required"}.

	Example:
	    // Use the OauthIdTokenValidatorMiddleware middleware to protect html routes.
		webserver.E.GET("/private", privateHandler, webserver.OauthIdTokenValidatorMiddleware)


		// Use the OauthIdTokenValidatorApiMiddleware middleware to protect API endpoints.
		webserver.E.GET("/api/private", privateApiHandler, webserver.OauthIdTokenValidatorApiMiddleware)

3.  Initialize the webserver by calling the Start function with the configuration:

	webserver.Start(config)

	This will:
	- Initialize the OIDC provider from Dex using oauthInitOidcProviderFromDex.
	- Set up the following routes:
		- /login: Initiates the OAuth 2.0 login process.
		- /callback: Handles the OAuth 2.0 callback from Dex.
		- /logout: Clears the ID token cookie.
	- Start the web server on port 8080.

Exported methods:

- Start: Initializes the OIDC provider and starts the web server.
- OauthIdTokenValidatorMiddleware: Middleware to validate the ID token in html routes.
- OauthIdTokenValidatorApiMiddleware: Middleware to validate the ID token in API routes.

Exported variables:

- E: Instance of the Echo web server.

Example: see main.go
*/
package webserver
