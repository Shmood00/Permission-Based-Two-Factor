package main

import (
	"Permission-Based-Two-Factor/apis/userAPI"
	"Permission-Based-Two-Factor/entities"
	"Permission-Based-Two-Factor/models"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
)

func main() {
	r := mux.NewRouter()

	//Declaring all APIs endpoints and methods they accetp
	r.HandleFunc("/api/user/authenticate", userAPI.CreateToken).Methods("POST")

	r.HandleFunc("/api/user/register", userAPI.RegisterUser).Methods("POST")

	r.HandleFunc("/api/user/forgot_password", userAPI.ForgotPassword).Methods("GET")
	r.HandleFunc("/api/user/forgot_password", userAPI.ForgotPassword).Methods("POST")

	r.HandleFunc("/api/user/security_questions", ValidateEmailConfirmation(userAPI.SecurityQuestions)).Methods("GET")
	r.HandleFunc("/api/user/security_questions", ValidateEmailConfirmation(userAPI.SecurityQuestions)).Methods("POST")
	r.HandleFunc("/api/user/change_password", ValidateEmailConfirmation(userAPI.ChangePassword)).Methods("GET")
	r.HandleFunc("/api/user/change_password", ValidateEmailConfirmation(userAPI.ChangePassword)).Methods("POST")

	r.HandleFunc("/api/user/add_device", ValidateMiddleware(userAPI.AddDevice)).Methods("POST")

	r.HandleFunc("/api/user/login", userAPI.WebLogin).Methods("GET")
	r.HandleFunc("/api/user/login", userAPI.WebLogin).Methods("POST")

	r.HandleFunc("/api/user/post_login", userAPI.PostLogin).Methods("GET")

	r.HandleFunc("/api/user/verify_device", ValidateMiddleware(userAPI.VerifyDevice)).Methods("POST")

	r.HandleFunc("/api/user/all_devices", ValidateMiddleware(userAPI.GetAllDevices)).Methods("GET")

	n := negroni.Classic()
	n.UseHandler(r)
	n.Run(":5000")

}

//Function wrapper that protects endpoints that require the user to have a JWT token in authorization header
func ValidateMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authorizationHeader := req.Header.Get("authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {
				token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("There was an error")
					}
					return []byte("secret"), nil
				})
				if error != nil {
					json.NewEncoder(w).Encode(models.Exception{Message: error.Error()})
					return
				}
				if token.Valid {
					context.Set(req, "decoded", token.Claims)

					next(w, req)
				} else {
					json.NewEncoder(w).Encode(models.Exception{Message: "Invalid authorization token"})
				}
			}
		} else {
			json.NewEncoder(w).Encode(models.Exception{Message: "An authorization header is required"})
		}
	})
}

//Wrapper function used to verify forgot password url sent in email to user
//Decodes base64 encoded JWT token for validation
func ValidateEmailConfirmation(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

		keys, err := req.URL.Query()["token"]

		if !err || len(keys[0]) == 0 {
			json.NewEncoder(w).Encode(entities.Message{Message: "Error, no token provided"})
		} else {

			decodedToken, tokErr := base64.StdEncoding.DecodeString(keys[0])

			if tokErr != nil {
				fmt.Println("Error decoding")
			} else {

				token, error := jwt.Parse(string(decodedToken), func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("Error occurred")
					} else {
						return []byte("secret"), nil
					}
				})

				if error != nil {
					json.NewEncoder(w).Encode(models.Exception{Message: error.Error()})
					return
				}

				if token.Valid {
					context.Set(req, "decoded", token.Claims)

					next(w, req)
				} else {
					json.NewEncoder(w).Encode(models.Exception{Message: "Invalid authorization token"})
				}
			}
		}

	})

}
