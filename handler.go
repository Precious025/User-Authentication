package main

import (
	"fmt"
	"net/http"

	"html/template"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Define the secret key used for signing the JWT
var mySecretKey = []byte("secret")

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func Login(w http.ResponseWriter, r *http.Request) {

	tmpl, err := template.ParseFiles("web/login.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//Handle login request
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Check if the username and password are correct
		if username == "myusername" && password == "mypassword" {
			expirationTime := time.Now().Add(5 * time.Minute)
			claims := &Claims{
				Username: username,
				StandardClaims: jwt.StandardClaims{
					ExpiresAt: expirationTime.Unix(),
					IssuedAt:  time.Now().Unix(),
				},
			}

			// Create a new JWT token with claims
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

			// Sign the token with the secret key
			signedToken, err := token.SignedString(mySecretKey)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			//set cookie to store token in browser
			http.SetCookie(w,
				&http.Cookie{
					Name:    "token",
					Value:   signedToken,
					Expires: expirationTime,
				})

			// Redirect the user to the home page
			http.Redirect(w, r, "/home", http.StatusFound)
			return

		}

		//parsing data to template
		data := struct {
			Message string
		}{
			Message: "Please enter your username and password",
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	data := struct {
		Message string
	}{
		Message: "Please enter your username and password",
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

func Home(w http.ResponseWriter, r *http.Request) {

	//serve home page
	tmpl, err := template.ParseFiles("web/home.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//get cookie
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//get token from cookie
	tokenString := cookie.Value

	//parse token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Return the key for validation
		return mySecretKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//check if token is valid
	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//get claims from token
	claims, ok := token.Claims.(*Claims)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//check if token is expired
	if time.Until(time.Unix(claims.ExpiresAt, 0)) < 0 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//check if token is valid
	if claims.Username != "myusername" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//excecute template
	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}
