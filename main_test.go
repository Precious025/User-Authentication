package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func TestLoginHandler(t *testing.T) {
	// Create a new request to the login endpoint with valid credentials
	form := url.Values{}
	form.Add("username", "myusername")
	form.Add("password", "mypassword")
	req, err := http.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(Login)
	handler.ServeHTTP(rr, req)

	// Check that the response status code is correct
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusFound)
	}

	// Check that a cookie was set
	if len(rr.Header().Get("Set-Cookie")) == 0 {
		t.Errorf("no cookie was set")
	}

	// Get the cookie and parse the token
	cookie, err := rr.Result().Cookies()[0], nil
	if err != nil {
		t.Fatal(err)
	}
	tokenString := cookie.Value
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return mySecretKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Check that the token is valid
	if !token.Valid {
		t.Errorf("token is not valid")
	}

	// Check that the token claims are correct
	if claims, ok := token.Claims.(*Claims); ok {
		if claims.Username != "myusername" {
			t.Errorf("claims.Username is incorrect")
		}
		if time.Until(time.Unix(claims.ExpiresAt, 0)) < 0 {
			t.Errorf("token is expired")
		}
	} else {
		t.Errorf("unable to parse token claims")
	}
}

func TestHomeHandler(t *testing.T) {
	// Create a new request to the home endpoint with a valid cookie
	req, err := http.NewRequest("GET", "/home", nil)
	if err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		Username: "myusername",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	})
	tokenString, err := token.SignedString(mySecretKey)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: time.Now().Add(5 * time.Minute),
	}
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(Home)
	handler.ServeHTTP(rr, req)

	// Check that the response status code is correct
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}
