package main

import (
	"context"
	"example/webserver"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var webserverConfigOauth = &webserver.ConfigOauthClientDex{
	ClientID:          "example-app",
	ClientSecret:      "ZXhhbXBsZS1hcHAtc2VjcmV0",
	ClientRedirectURL: "http://127.0.0.1:8080/callback",
	ClientScopes:      []string{"openid", "profile", "email", "groups"},
	DexIssuer:         "http://127.0.0.1:5556/dex",
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// ------------- Handlers ------------------------

// / indexHandler serves the index page with links to other pages.
func indexHandler(c echo.Context) error {
	html := `<html>
		<body>
			<h1>Index</h1>
			<ul>
				<li><a href="/public">Public</a></li>
				<li><a href="/login">Login</a></li>
				<li><a href="/logout">Logout</a></li>
				<li><a href="/private">Private</a></li>
				<li><a href="/date_from_server">Server Date</a></li>
			</ul>
			</p><hr></p>
		</body>
	</html>`
	return c.HTML(http.StatusOK, html)
}

// privateHandler serves /private the private page, which is only accessible
// if the user is already authenticated (contains valid ID token as cookie).
func privateHandler(c echo.Context) error {

	// The cookie-and-claims code bellow is not necessary, as the authMiddleware already took care of verifying the ID token before reaching this handler.
	// This code is left here as an example of how to extract claims from the ID token.
	cookie, err := c.Cookie("id_token")
	if err != nil {
		return c.String(http.StatusUnauthorized, "Missing ID token")
	}

	idToken, err := webserver.OidcVerifier.Verify(context.Background(), cookie.Value)
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
				<li><a href="/date_from_server">Server Date</a></li>
			</ul>
			</p><hr></p>
		</body>
	</html>`, cookie.Value, claims))
}

// dateFromServerHandler serves an HTML page with JavaScript that connects to the /ws_date websocket.
func dateFromServerHandler(c echo.Context) error {
	return c.HTML(http.StatusOK, `<html>
		<body>
			<ul>
				<li><a href="/public">Public</a></li>
				<li><a href="/login">Login</a></li>
				<li><a href="/logout">Logout</a></li>
				<li><a href="/private">Private</a></li>
				<li><a href="/date_from_server">Server Date</a></li>
			</ul>
			<h1>Server Date</h1>
			<div id="serverDate">Connecting...</div>
			<script>
				const ws = new WebSocket("ws://" + location.host + "/ws_date");
				ws.onmessage = (e) => {
					const data = JSON.parse(e.data);
					document.getElementById("serverDate").innerText += "\n" + data.timestamp;
					};
				ws.onerror = (e) => {
					console.error('WebSocket error:', e);
					alert('WebSocket error occurred. Please check the console for details.');
				};
				ws.onclose = (e) => {
					if (e.code === 1006) {
						// Check if the close was due to a 401 Unauthorized error
						try {
							const errorData = JSON.parse(e.reason);
							if (errorData.error === "Login required") {
								alert("Authentication required. Please log in.");
								window.location.href = "/"; // Redirect to the index page
								return;
							}
						} catch (jsonError) {
							console.error("Failed to parse close reason as JSON:", e.reason, jsonError);
							alert("WebSocket connection closed unexpectedly. Please check the console for details.");
						}
					} else {
						console.warn('WebSocket connection closed:', e);
						alert('WebSocket connection closed. Please check the console for details.');
					}
				};
			</script>
		</body>
	</html>`)
}

type DateMessage struct {
	Timestamp string `json:"timestamp"`
}

// dateSocketHandlerApi upgrades the HTTP connection to a websocket and periodically sends the current date/time to the client.
func dateSocketHandlerApi(c echo.Context) error {
	ws, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		return err
	}
	defer ws.Close()

	for {
		time.Sleep(time.Second)
		msg := DateMessage{
			Timestamp: time.Now().String(),
		}
		if err := ws.WriteJSON(msg); err != nil {
			return err
		}
	}
}

func initWebserver() {
	E := webserver.E

	// ------------- Middlewares ------------------------
	// Configure colored logging middleware
	E.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "\033[1;34m[${time_rfc3339}]\033[0m \033[1;37m${method}\033[0m \033[1;32m${status}\033[0m ${uri} \t\t\t\t${latency}ns\n",
	}))
	E.Use(middleware.Recover())

	// ------------- Routes -----------------------------
	// Group routes for public html pages
	publicGroup4HtmlWebs := E.Group("")
	publicGroup4HtmlWebs.GET("/", indexHandler)
	publicGroup4HtmlWebs.GET("/public", func(c echo.Context) error {
		return c.HTML(http.StatusOK, `<html>
			<body>
				<h1>Public Page</h1>
				<p>This is a public page.</p>
				<ul>
					<li><a href="/public">Public</a></li>
					<li><a href="/login">Login</a></li>
					<li><a href="/logout">Logout</a></li>
					<li><a href="/private">Private</a></li>
					<li><a href="/date_from_server">Server Date</a></li>
				</ul>
				</p><hr></p>
			</body>
		</html>`)
	})
	publicGroup4HtmlWebs.GET("/date_from_server", dateFromServerHandler)

	// Group routes for private html pages (use the OauthIdTokenValidatorMiddleware)
	// If the user is not authenticated, the OauthIdTokenValidatorMiddleware redirects to /login.
	privateGroup4HtmlWebs := E.Group("")
	privateGroup4HtmlWebs.Use(webserver.OauthIdTokenValidatorMiddleware)
	privateGroup4HtmlWebs.GET("/private", privateHandler)

	// Group routes for private API endpoints (use the OauthIdTokenValidatorApiMiddleware)
	// If the user is not authenticated, the OauthIdTokenValidatorApiMiddleware returns a 401 Unauthorized with json-body {"error": "Login required"}.
	privateGroup4ApiWebs := E.Group("")
	privateGroup4ApiWebs.Use(webserver.OauthIdTokenValidatorApiMiddleware)
	privateGroup4ApiWebs.GET("/ws_date", dateSocketHandlerApi)

}

func main() {
	// initWebserver() - where Echo config can be made: middleware, routes, ...
	initWebserver()

	webserver.Start(webserverConfigOauth)
}
