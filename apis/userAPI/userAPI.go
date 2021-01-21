package userAPI

import (
	"Permission-Based-Two-Factor/config"
	"Permission-Based-Two-Factor/entities"
	"Permission-Based-Two-Factor/models"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

func CreateToken(w http.ResponseWriter, r *http.Request) {

	var user entities.UserWithPassword

	_ = json.NewDecoder(r.Body).Decode(&user)

	//Check to ensure data exists in the POST
	if len(user.Name) > 0 && len(user.Password) > 0 {

		db, err := config.GetDB()

		if err != nil {
			fmt.Println(err)
		} else {
			userModel := models.UserModel{
				Db: db,
			}

			//Check if user exists in db
			users, verifyErr := userModel.VerifyUser(user.Name, user.Password)

			if verifyErr != nil {
				json.NewEncoder(w).Encode("Unable to verify credentials.")
			} else {

				//Encode jwt token for user, set expiry for 30 minutes
				expiry := time.Now().Add(time.Minute * 30).Unix()

				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"using_iot": users[0].UsingIOT,
					"name":      users[0].Name,
					"expiry":    expiry,
					"public_id": users[0].PublicID,
				})

				//Sign token with secret **should be read from file on server and should be complex
				tokenString, error := token.SignedString([]byte("secret"))

				if error != nil {
					json.NewEncoder(w).Encode("An error occured creating your token.")
				}

				//Respond with JWT token
				json.NewEncoder(w).Encode(models.JWTToken{Token: tokenString})

			}
		}
	} else {

		//Error message if user does not exist in db
		msg := entities.Message{
			Message: "Invalid credentials provided",
		}

		json.NewEncoder(w).Encode(msg)
	}

}

//Register user endpoint
func RegisterUser(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {

		var user entities.UserRegister
		_ = json.NewDecoder(r.Body).Decode(&user)

		//Ensure data exists within the POST
		if len(user.Name) > 0 && len(user.Email) > 0 && len(user.ConfirmEmail) > 0 && len(user.Password) > 0 && len(user.ConfirmPassword) > 0 && len(user.Question1) > 0 && len(user.Question2) > 0 && len(user.Question3) > 0 && len(user.Answer1) > 0 && len(user.Answer2) > 0 && len(user.Answer3) > 0 {

			//Security Questions
			var validQuestions [6]string

			validQuestions[0] = "What are the last four digits of your national insurance or social security number?"
			validQuestions[1] = "What is your oldest cousins first name?"
			validQuestions[2] = "What was your childhood nickname?"
			validQuestions[3] = "In what city or town did your parents meet?"
			validQuestions[4] = "What is your grandmother's maiden name?"
			validQuestions[5] = "What is your first child's nickname?"

			//Hashing the password and 3 security answers
			hashedPass, err := bcrypt.GenerateFromPassword([]byte(user.Password), 8)
			secAnswer1, secerr1 := bcrypt.GenerateFromPassword([]byte(user.Answer1), 8)
			secAnswer2, secerr2 := bcrypt.GenerateFromPassword([]byte(user.Answer2), 8)
			secAnswer3, secerr3 := bcrypt.GenerateFromPassword([]byte(user.Answer3), 8)

			db, err := config.GetDB()

			if err != nil {
				fmt.Println("Error")
			} else {
				userModel := models.UserModel{
					Db: db,
				}
				//Ensure email and confirmed email match
				if user.Email == user.ConfirmEmail {

					//Compare passwords
					passwordNoMatch := bcrypt.CompareHashAndPassword(hashedPass, []byte(user.ConfirmPassword))

					//Throw error if passwords do not match
					if passwordNoMatch != nil && passwordNoMatch == bcrypt.ErrMismatchedHashAndPassword {

						passErrorMsg := entities.Message{
							Message: "Passwords do not match.",
						}

						json.NewEncoder(w).Encode(passErrorMsg)

					} else {

						//Check if securtiy questions chosen are within the list declared above
						if contains(validQuestions, user.Question1) && contains(validQuestions, user.Question2) && contains(validQuestions, user.Question3) {
							if secerr1 != nil && secerr2 != nil && secerr3 != nil {
								fmt.Println("Error hashing security answers.")
							} else {

								//Add user to the database
								registerUser := userModel.RegisterUser(user.Name, user.Email, string(hashedPass), user.Question1, user.Question2, user.Question3, string(secAnswer1), string(secAnswer2), string(secAnswer3))

								//Return partial information of user just registered
								newUser := entities.User{
									PublicID: registerUser[0].PublicID,
									Name:     registerUser[0].Name,
									UsingIOT: registerUser[0].UsingIOT,
								}

								json.NewEncoder(w).Encode(newUser)
							}
						} else {

							//Error message if incorrect security questions are used
							goodQuestions := entities.ValidQuestions{
								Message: "Security questions must be one of the following",
								Q1:      validQuestions[0],
								Q2:      validQuestions[1],
								Q3:      validQuestions[2],
								Q4:      validQuestions[3],
								Q5:      validQuestions[4],
								Q6:      validQuestions[5],
							}

							json.NewEncoder(w).Encode(goodQuestions)
						}

					}

				}

			}
		} else {

			//If no / incorrect data is fed into POST
			msg := entities.Message{
				Message: "Invalid credentials provided",
			}

			json.NewEncoder(w).Encode(msg)
		}

	}
}

//Forgot password endpoint
func ForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {

		var user entities.ForgotPassword
		_ = json.NewDecoder(r.Body).Decode(&user)

		//Ensure data is within the POST
		if len(user.Email) > 0 {

			db, err := config.GetDB()

			if err != nil {
				fmt.Println("Error")
			} else {

				userModel := models.UserModel{
					Db: db,
				}

				//Verify email exists within db
				userEmail, verifyErr := userModel.VerifyEmail(user.Email)

				//If verification fails
				if len(userEmail) == 0 {
					msg := entities.Message{
						Message: "Invalid credentials",
					}

					json.NewEncoder(w).Encode(msg)

				} else {

					if verifyErr != nil {
						msg := entities.Message{
							Message: "Invalid credentials",
						}

						json.NewEncoder(w).Encode(msg)
					} else {

						//Create temporary token for user to answer security questions
						expiry := time.Now().Add(time.Minute * 15).Unix()

						token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
							"email":  userEmail[0].Email,
							"expiry": expiry,
						})

						//Sign token with secret
						tokenString, error := token.SignedString([]byte("secret"))

						//Base64 encode token to be passed into url
						encodedToken := base64.StdEncoding.EncodeToString([]byte(tokenString))

						if error != nil {
							fmt.Println("Error")
						} else {

							//Send message to user with proper temp token and link to answer sec questions
							msg := entities.Message{
								Message: "http://35.243.198.103:5000/api/user/security_questions?token=" + encodedToken,
							}

							json.NewEncoder(w).Encode(msg)

						}

					}
				}

			}
		} else {
			//If incorrect / no data is passed into POST
			msg := entities.Message{
				Message: "Invalid credentials provided",
			}

			json.NewEncoder(w).Encode(msg)
		}

	}
}

//Dealing with user's answering security questions
func SecurityQuestions(w http.ResponseWriter, r *http.Request) {

	if r.Method == "GET" {

		//Grab encoded JWT token from URL
		keys := r.URL.Query()["token"]

		//Decode base64
		decodedToken, decodeErr := base64.StdEncoding.DecodeString(keys[0])

		if decodeErr != nil {

			fmt.Println("Could not decode base64.")

		} else {

			//Decoding JWT token
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

			//Extracting JWT payload
			newFormatToken, newErr := ExtractClaims(string(decodedToken))
			if token.Valid {
				if newErr != true {
					payloadErr := entities.Message{
						Message: "Error extracting payload from JWT token.",
					}

					json.NewEncoder(w).Encode(payloadErr)
				} else {

					//Query db with uers email to figure out what questions they chose
					userEmail := newFormatToken["email"]

					db, dbErr := config.GetDB()

					if dbErr != nil {
						fmt.Println("Error")
					} else {
						userModel := models.UserModel{
							Db: db,
						}

						userQuestions, userQErr := userModel.GetSecurityQuestions(userEmail.(string))

						if userQErr != nil {
							secQErr := entities.Message{
								Message: "Error retrieving your security questions.",
							}

							json.NewEncoder(w).Encode(secQErr)

						} else {

							//Display user their security questions
							quest := entities.SecurityQuestion{
								SecQues1: userQuestions[0].SecQues1,
								SecQues2: userQuestions[0].SecQues2,
								SecQues3: userQuestions[0].SecQues3,
							}

							json.NewEncoder(w).Encode(quest)
						}

					}
				}
			}
		}
	} else if r.Method == "POST" {

		keys := r.URL.Query()["token"]

		var user entities.SecurityAnswer
		_ = json.NewDecoder(r.Body).Decode(&user)

		//Ensuring data exists within the POST
		if len(user.Ans1) > 0 && len(user.Ans2) > 0 && len(user.Ans3) > 0 {

			//Decode base64
			decodedToken, decodeErr := base64.StdEncoding.DecodeString(keys[0])

			if decodeErr != nil {
				fmt.Println("Could not decode bas64.")
			} else {

				//Decode JWT token
				token, error := jwt.Parse(string(decodedToken), func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("Error occurred")
					} else {
						return []byte("secret"), nil
					}
				})

				if error != nil {
					decodeTokenErr := entities.Message{
						Message: "Could not decode JWT token.",
					}

					json.NewEncoder(w).Encode(decodeTokenErr)
				}

				//Extract payload from JWT token
				newFormatToken, newErr := ExtractClaims(string(decodedToken))
				if token.Valid {
					if newErr != true {
						payloadJWTErr := entities.Message{
							Message: "Unable extracting JWT payload.",
						}

						json.NewEncoder(w).Encode(payloadJWTErr)
					} else {

						//Get user email
						userEmail := newFormatToken["email"]

						db, dbErr := config.GetDB()

						if dbErr != nil {
							fmt.Println("Error")
						} else {
							userModel := models.UserModel{
								Db: db,
							}

							//Grab user's answers stored in db
							userAnswers, ansErr := userModel.GetSecurityAnswers(userEmail.(string))

							if ansErr != nil {
								getAnsErr := entities.Message{
									Message: "Unable to retrieve answers.",
								}

								json.NewEncoder(w).Encode(getAnsErr)
							} else {

								//Compare posted securtiy answers with ones stored in db
								ans1Match := bcrypt.CompareHashAndPassword([]byte(userAnswers[0].Ans1), []byte(user.Ans1))
								ans2Match := bcrypt.CompareHashAndPassword([]byte(userAnswers[0].Ans2), []byte(user.Ans2))
								ans3Match := bcrypt.CompareHashAndPassword([]byte(userAnswers[0].Ans3), []byte(user.Ans3))

								if ans1Match != nil && ans1Match == bcrypt.ErrMismatchedHashAndPassword {
									ansNoMatch := entities.Message{
										Message: "Answers do not match.",
									}

									json.NewEncoder(w).Encode(ansNoMatch)
								} else {

									if ans2Match != nil && ans2Match == bcrypt.ErrMismatchedHashAndPassword {
										ansNoMatch := entities.Message{
											Message: "Answers do not match.",
										}

										json.NewEncoder(w).Encode(ansNoMatch)
									} else {
										if ans3Match != nil && ans3Match == bcrypt.ErrMismatchedHashAndPassword {
											ansNoMatch := entities.Message{
												Message: "Answers do not match.",
											}

											json.NewEncoder(w).Encode(ansNoMatch)
										} else {

											//Return link for users to reset their password
											link := entities.ChangePasswordLink{
												Link: "http://35.243.198.103:5000/api/user/change_password?token=" + keys[0],
											}

											json.NewEncoder(w).Encode(link)

										}
									}

								}

							}

						}

					}
				}
			}
		} else {

			//Invalid / emmpty data is found in POST
			json.NewEncoder(w).Encode(entities.Message{Message: "Invalid Credentials Provided"})
		}
	}
}

//Actually change the user password
func ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {

		var user entities.ResetPassword
		_ = json.NewDecoder(r.Body).Decode(&user)

		//Check if there's data in POST
		if len(user.Password) > 0 && len(user.ConfirmPassword) > 0 {

			hashedPass, err := bcrypt.GenerateFromPassword([]byte(user.Password), 8)
			confPass := user.ConfirmPassword

			if err != nil {
				hashErr := entities.Message{
					Message: "Error hashing password.",
				}

				json.NewEncoder(w).Encode(hashErr)

			} else {

				//Grab token from URL
				keys := r.URL.Query()["token"]

				//Decodeb base64
				decodedToken, decodeErr := base64.StdEncoding.DecodeString(keys[0])

				if decodeErr != nil {
					fmt.Println("Error decoding base64.")
				} else {

					//Decode JWT token
					token, error := jwt.Parse(string(decodedToken), func(token *jwt.Token) (interface{}, error) {
						if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
							return nil, fmt.Errorf("Error occurred")
						} else {
							return []byte("secret"), nil
						}
					})

					if error != nil {
						tokenDecodeErr := entities.Message{
							Message: "Error deconding JWT token.",
						}

						json.NewEncoder(w).Encode(tokenDecodeErr)
					}

					//Extracting JWT payload
					newFormatToken, newErr := ExtractClaims(string(decodedToken))
					if token.Valid {
						if newErr != true {
							extractPayloadErr := entities.Message{
								Message: "Error extracting JWT payload.",
							}

							json.NewEncoder(w).Encode(extractPayloadErr)

						} else {

							db, dbErr := config.GetDB()

							//Grab user email
							userEmail := newFormatToken["email"]

							if dbErr != nil {
								fmt.Println("Error")
							} else {
								userModel := models.UserModel{
									Db: db,
								}

								//Comparing newly entered passwords
								passwordNoMatch := bcrypt.CompareHashAndPassword(hashedPass, []byte(confPass))

								if passwordNoMatch != nil && passwordNoMatch == bcrypt.ErrMismatchedHashAndPassword {
									passMatchErr := entities.Message{
										Message: "Passwords do not match.",
									}

									json.NewEncoder(w).Encode(passMatchErr)

								} else {

									//Update old password with new one
									updatePass := userModel.UpdatePassword(string(hashedPass), userEmail.(string))

									msg := entities.Message{
										Message: updatePass,
									}

									json.NewEncoder(w).Encode(msg)

								}
							}

						}
					}
				}
			}
		} else {

			//Incorrect / empty data in POST
			json.NewEncoder(w).Encode(entities.Message{Message: "Invalid credentials provided"})
		}
	}
}

//Adding new device to user account
func AddDevice(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {

		var device entities.Device

		_ = json.NewDecoder(r.Body).Decode(&device)

		//Check if there is POST data
		if len(device.Name) == 0 {
			msg := entities.Message{
				Message: "Incorrect information provded.",
			}

			json.NewEncoder(w).Encode(msg)

		} else {

			db, err := config.GetDB()

			if err != nil {
				fmt.Println("Error")
			} else {
				userModel := models.UserModel{
					Db: db,
				}

				//Get JWT token
				authorizationHeader := r.Header.Get("authorization")

				//Decode JWT token
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
							decodeErr := entities.Message{
								Message: "Unable to decode token.",
							}

							json.NewEncoder(w).Encode(decodeErr)
						}

						if token.Valid {

							//Extract JWT payload
							newformat, boolErr := ExtractClaims(bearerToken[1])

							if boolErr != true {
								payloadErr := entities.Message{
									Message: "Unable to decode token.",
								}

								json.NewEncoder(w).Encode(payloadErr)
							} else {

								//Add device to db
								device := userModel.AddDevice(device.Name, newformat["public_id"].(string))

								msg := entities.Message{
									Message: device,
								}

								json.NewEncoder(w).Encode(msg)

							}

						} else {
							json.NewEncoder(w).Encode(models.Exception{Message: "Invalid authorization token"})
						}
					}
				} else {
					json.NewEncoder(w).Encode(models.Exception{Message: "An authorization header is required"})
				}

			}
		}
	} else {
		//If incorrect / no data is passed into POST
		msg := entities.Message{
			Message: "Invalid credentials provided",
		}

		json.NewEncoder(w).Encode(msg)
	}
}

//Device verification
func VerifyDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {

		var device entities.VerifyDevice

		_ = json.NewDecoder(r.Body).Decode(&device)

		//Check if there's POST data
		if len(device.PublicID) > 0 {

			//Get JWT token
			authorizationHeader := r.Header.Get("authorization")

			//Decode JWT token
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
						json.NewEncoder(w).Encode(models.Exception{Message: "Error decoding token."})
						return

					}
					if token.Valid {

						//Extract payload from JWT token
						newformat, boolErr := ExtractClaims(bearerToken[1])

						if boolErr != true {
							json.NewEncoder(w).Encode(models.Exception{Message: "Error extracting JWT payload."})
						} else {

							db, err := config.GetDB()

							if err != nil {
								fmt.Println("Error")
							} else {
								userModel := models.UserModel{
									Db: db,
								}

								//Verify the device with db
								msg := userModel.VerifyDevice(newformat["public_id"].(string), device.PublicID)

								json.NewEncoder(w).Encode(entities.Message{Message: msg})

							}

						}

						//Errors thrown
					} else {
						json.NewEncoder(w).Encode(models.Exception{Message: "Invalid authorization token"})
					}
				}
			} else {
				json.NewEncoder(w).Encode(models.Exception{Message: "An authorization header is required"})
			}
		} else {
			json.NewEncoder(w).Encode(entities.Message{Message: "Invalid credentials provided"})
		}
	}
}

//Web application login
func WebLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {

		//Render HTML page for users logging in
		temp, _ := template.ParseFiles("login.html")

		temp.Execute(w, "login.html")

	} else if r.Method == "POST" {
		r.ParseForm()
		db, err := config.GetDB()

		//Get user inputed data from form
		name := r.Form["name"][0]
		password := r.Form["password"][0]

		if err != nil {
			fmt.Println("Error")
		} else {
			userModel := models.UserModel{
				Db: db,
			}

			//Check if user exists in db
			users, verifyErr := userModel.VerifyUser(name, password)

			//Check if query returns user
			if len(users) == 0 {
				json.NewEncoder(w).Encode("Unable to verify credentials.")
			} else {
				if verifyErr != nil {
					json.NewEncoder(w).Encode(entities.Message{Message: "Unable to verify credentials."})
				} else {

					//Encode jwt token for user

					expiry := time.Now().Add(time.Minute * 30).Unix()

					token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
						"using_iot": users[0].UsingIOT,
						"name":      users[0].Name,
						"expiry":    expiry,
						"public_id": users[0].PublicID,
					})

					tokenString, error := token.SignedString([]byte("secret"))

					//Generate a cookie with JWT token as the value
					cookie := http.Cookie{
						Name:    "jwt_token",
						Value:   tokenString,
						Expires: time.Now().Add(time.Minute * 30),
						HttpOnly: true,
						SameSite: http.SameSiteLaxMode,
					}

					//Set user cookie
					http.SetCookie(w, &cookie)

					if error != nil {
						json.NewEncoder(w).Encode("An error occured creating your token.")
					}

					//Redirect user to view their information
					http.Redirect(w, r, "/api/user/post_login", 301)
				}
			}
		}

	}
}

//Page that displays users information
func PostLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		temp, _ := template.ParseFiles("post_login.html")

		//Read token from cookie
		user_token, cookieError := r.Cookie("jwt_token")

		//Redirect user to login if no cookie is present
		if cookieError != nil {

			http.Redirect(w, r, "/api/user/login", 301)
		} else {
			//Decode JWT token
			token, error := jwt.Parse(string(user_token.Value), func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Error occurred")
				} else {
					return []byte("secret"), nil
				}
			})

			if error != nil {
				json.NewEncoder(w).Encode(models.Exception{Message: "Unable to decode JWT token."})
			}

			//Extract JWT payload
			newFormatToken, newErr := ExtractClaims(user_token.Value)
			if token.Valid {
				if newErr != true {
					fmt.Println("Error")
				} else {

					//Determine user's permission levels
					//First check if user is using n IoT devce
					if newFormatToken["using_iot"] == false {

						loggedInUser := entities.User{
							Name:     newFormatToken["name"].(string),
							PublicID: newFormatToken["public_id"].(string),
							UsingIOT: newFormatToken["using_iot"].(bool),
						}

						temp.ExecuteTemplate(w, "post_login.html", loggedInUser)

						//IoT device is in use
					} else {

						db, err := config.GetDB()

						if err != nil {
							fmt.Print("Error")
						} else {
							userModel := models.UserModel{
								Db: db,
							}

							//Check if IoT device has been verified
							result := userModel.IsDeviceVerified(newFormatToken["public_id"].(string))

							if result == "true" {
								convertResult, boolerr := strconv.ParseBool(result)

								if boolerr != nil {
									fmt.Println("conversion error")
								} else {

									//Grab user's security questions using their public_id
									secQ, getSecQErr := userModel.GetSecurityQuestionsPubID(newFormatToken["public_id"].(string))

									if getSecQErr != nil {
										fmt.Println("Error")
									} else {

										//Grab user email using public_id
										userEmail, userEmailErr := userModel.GetEmail(newFormatToken["public_id"].(string))

										if userEmailErr != nil {
											fmt.Println("Error")
										} else {

											loggedInUser := entities.UserWithEmail{
												Name:       newFormatToken["name"].(string),
												Email:      userEmail[0].Email,
												PublicID:   newFormatToken["public_id"].(string),
												UsingIOT:   newFormatToken["using_iot"].(bool),
												Question1:  secQ[0].SecQues1,
												Question2:  secQ[0].SecQues2,
												Question3:  secQ[0].SecQues3,
												IsVerified: convertResult,
											}

											temp.ExecuteTemplate(w, "post_login.html", loggedInUser)
										}
									}
								}

								//Device is not verified
							} else {
								convertResult, boolerr := strconv.ParseBool(result)

								if boolerr != nil {
									fmt.Println("conversion error")
								} else {

									loggedInUser := entities.UserDeviceVer{
										Name:       newFormatToken["name"].(string),
										PublicID:   newFormatToken["public_id"].(string),
										UsingIOT:   newFormatToken["using_iot"].(bool),
										IsVerified: convertResult,
									}

									temp.ExecuteTemplate(w, "post_login.html", loggedInUser)
								}
							}

						}

					}
				}
			}
		}

	}
}

//Return list of user's IoT devices
func GetAllDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {

		//Check for JWT token in authorization header
		authorizationHeader := r.Header.Get("authorization")

		//Decode token
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
					json.NewEncoder(w).Encode(models.Exception{Message: "Unable to decode token."})
				}

				//Extracting JWT token payload
				if token.Valid {
					newformat, boolErr := ExtractClaims(bearerToken[1])

					if boolErr != true {
						fmt.Println("error")
					} else {

						db, err := config.GetDB()

						if err != nil {
							fmt.Println("Error")
						} else {
							userModel := models.UserModel{
								Db: db,
							}

							//Query db for list of user devices
							dev := userModel.GetAllDevices(newformat["public_id"].(string))

							json.NewEncoder(w).Encode(dev)

						}

					}

				} else {
					json.NewEncoder(w).Encode(models.Exception{Message: "Invalid authorization token"})
				}
			}
		} else {
			json.NewEncoder(w).Encode(models.Exception{Message: "An authorization header is required"})
		}
	}
}

//Function for determining if use rentered security questions exist within the default list made
func contains(arr [6]string, str string) bool {
	for _, q := range arr {

		if q == str {
			return true
		}
	}

	return false
}

//Extracting JWT payload information
func ExtractClaims(tokenStr string) (jwt.MapClaims, bool) {

	//Secret used to sign JWT token
	hmacSecretString := "secret"
	hmacSecret := []byte(hmacSecretString)
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		//Check token signing method
		return hmacSecret, nil
	})

	if err != nil {
		return nil, false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, true
	} else {
		fmt.Println("Invalid JWT Token")
		return nil, false
	}
}
