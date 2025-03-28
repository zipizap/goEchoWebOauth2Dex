package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/zipizap/goEchoWebOauth2Dex/webserver"

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

	var claims map[string]interface{}
	claimsInterface := c.Get("idTokenClaims")
	if claimsInterface != nil { // If the claims are not nil, cast them to the correct type
		claims = claimsInterface.(map[string]interface{})
	}
	// If the claims are nil, the user is not authenticated and the page should not be served.
	if claims == nil {
		return c.String(http.StatusUnauthorized, "Login required")
	}

	return c.HTML(http.StatusOK, fmt.Sprintf(`<html>
		<body>
			<h1>Private</h1>
			<p>Private access granted</p>
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
	</html>`, claims))
}

func checkAuthHandler(c echo.Context) error {
	cookie, err := c.Cookie("id_token")
	if err != nil {
		return c.JSON(http.StatusOK, map[string]bool{"authenticated": false})
	}
	_, err = webserver.OidcVerifier.Verify(context.Background(), cookie.Value)
	if err != nil {
		return c.JSON(http.StatusOK, map[string]bool{"authenticated": false})
	}
	return c.JSON(http.StatusOK, map[string]bool{"authenticated": true})
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
				fetch("/check_auth")
				.then(response => response.json())
				.then(data => {
					if(data.authenticated){
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
							if (e.code === 404) {
								try {
									const errorData = JSON.parse(e.reason);
									`+"alert(`HTTP ${e.code}: ${JSON.stringify(errorData)}`);"+`
								} catch (jsonError) {
									`+"alert(`HTTP ${e.code}: ${e.reason}`);"+`
								}
								return;
							} else if (e.code === 1006) {
								try {
									const errorData = JSON.parse(e.reason);
									if (errorData.error === "Login required") {
										alert("Authentication required. Please log in.");
										window.location.href = "/login";
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
					} else {
						// Redirect to login page with current url as parameter
						window.location.href = "/login?redirect=" + encodeURIComponent(window.location.pathname);
					}
				})
				.catch(err => {
					console.error("Error checking authentication:", err);
					alert("Error checking authentication.");
				});
			</script>
		</body>
	</html>`)
}

type DateMessage struct {
	Timestamp string `json:"timestamp"`
}

// dateSocketHandlerApi upgrades the HTTP connection to a websocket and periodically sends the current date/time to the client.
// dateSocketHandlerApi will never return error - if there is a problem, it will send a json-body
// error message {"error": "error description"} and close the ws-connection.
func dateSocketHandlerApi(c echo.Context) error {
	ws, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		// DO NOT RETURN ERROR, as the client is already expecting a websocket
		// If upgrading the connection fails AFTER the authentication middleware,
		// it's a server error, not an authentication error.
		// Send a close message to the client.
		ws.WriteJSON(map[string]string{"error": "Server error upgrading websocket"})
		ws.Close()
		return nil
	}
	defer ws.Close()

	for {
		time.Sleep(time.Second)
		msg := DateMessage{
			Timestamp: time.Now().String(),
		}
		if err := ws.WriteJSON(msg); err != nil {
			// DO NOT RETURN ERROR, as the client is already expecting a websocket
			// If writing the date fails AFTER the websocket was established,
			// it's a server error, not an authentication error.
			// Send a close message to the client.
			ws.WriteJSON(map[string]string{"error": "Server error sending date"})
			ws.Close()
			return nil
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
	// dateFromServerHandler serves an public HTML page exemplifying how to connecto to a private websocket
	// The js before connecting to the websocket, validates if user is authenticated (using api endpoint /check_auth)
	// If it is not authenticated, it redirects to the login page which then redirects back to the original page after login.
	// This is how a single-page-app like react, can connect to a websocket behind authentication
	publicGroup4HtmlWebs.GET("/date_from_server", dateFromServerHandler)

	// NEW: Group routes for public API endpoints
	publicGroup4ApiWebs := E.Group("")
	publicGroup4ApiWebs.GET("/check_auth", checkAuthHandler)

	// Group routes for private html pages (use the OauthIdTokenValidatorMiddleware)
	privateGroup4HtmlWebs := E.Group("")
	privateGroup4HtmlWebs.Use(webserver.OauthIdTokenValidatorMiddleware)
	privateGroup4HtmlWebs.GET("/private", privateHandler)

	// Group routes for private API endpoints (use the OauthIdTokenValidatorApiMiddleware)
	privateGroup4ApiWebs := E.Group("")
	privateGroup4ApiWebs.Use(webserver.OauthIdTokenValidatorApiMiddleware)
	privateGroup4ApiWebs.GET("/ws_date", dateSocketHandlerApi)

}

func main() {
	// initWebserver() - where Echo config can be made: middleware, routes, ...
	initWebserver()

	webserver.Start(webserverConfigOauth)
}
