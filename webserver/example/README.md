# Go OAuth2 + Dex Demo

This is a Golang app that implements the OAuth2 flow using Dex as the IDP (Identity Provider).

## Overview
- The app config is in main.go, pointing to Dex for OAuth2.
- Dex config is managed in dex_stuff/dex-config.local.yaml.

## Demo Flow
1. Launch Dex: `./01_launch_dex.sh`  
2. Launch the Go app: `./02_go_run.sh`  
3. Open http://127.0.0.1:8080/ in a browser.
4. Check http://127.0.0.1:8080/public page (always accessible).
5. Check http://127.0.0.1:8080/private page; it redirects to Dex to log in.
6. After successful login, an "id_token" cookie is saved. http://127.0.0.1:8080/private is now accessible.
7. Logout via http://127.0.0.1:8080/logout to clear the cookie; http://127.0.0.1:8080/private becomes inaccessible again.


This app code is the barebones implementation of the OAuth2 flow. It's meant to be a starting point for integrating OAuth2 into your app. Should be enough as is for basic use cases.

DEX acts like an hub-to-IDPs. Your app is configured for DEX, and DEX can then be (re)configured to use one-or-more OAuth2 providers. This simplifies your app code (that does not change), by moving the complexity of setting-up providers into DEX - which can be changed over time with more providers like Google, Azure, GitHub, etc



## Configuration

### DEX: (aka issuer)

http://127.0.0.1:5556/dex

Connector: `mockCallback` or Email/pass: `admin@example.com // password`

### App: (aka client)

homepage:     http://127.0.0.1:8080  

CLIENT_ID: example-app  

CLIENT_SECRET: ZXhhbXBsZS1hcHAtc2VjcmV0  

REDIRECT_URL: http://127.0.0.1:8080/callback  


