module example

go 1.24.0

require (
	github.com/coreos/go-oidc/v3 v3.13.0
	github.com/gorilla/websocket v1.5.3
	github.com/labstack/echo/v4 v4.13.3
	github.com/zipizap/goEchoWebOauth2Dex/webserver v0.0.0-20250326233047-189ef4f02734
	golang.org/x/oauth2 v0.28.0
)

// Replace the remote module with the local directory
replace github.com/zipizap/goEchoWebOauth2Dex/webserver => ../

require (
	github.com/go-jose/go-jose/v4 v4.0.5 // indirect
	github.com/labstack/gommon v0.4.2 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	golang.org/x/crypto v0.36.0 // indirect
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	golang.org/x/time v0.11.0 // indirect
)
