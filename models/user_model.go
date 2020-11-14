package models

import (
	"Permission-Based-Two-Factor/entities"
	"database/sql"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

//Defining some simple structs
type UserModel struct {
	Db *sql.DB
}
type JWTToken struct {
	Token string `json:"token"`
}

type Exception struct {
	Message string `json:"message"`
}

//Function for
func (userModel UserModel) SearchPublicID(public_id string) (user []entities.User, err error) {
	rows, err := userModel.Db.Query("select * from user where public_id = ?", public_id)
	if err != nil {
		return nil, err
	} else {
		var users []entities.User
		for rows.Next() {
			var id int64
			var publicID string
			var name string
			var email string
			var password string
			var usingIOT bool
			var secQ1 string
			var secQ2 string
			var secQ3 string
			var secA1 string
			var secA2 string
			var secA3 string

			scanErr := rows.Scan(&id, &publicID, &name, &email, &password, &usingIOT, &secQ1, &secQ2, &secQ3, &secA1, &secA2, &secA3)

			if scanErr != nil {
				return nil, scanErr
			} else {
				user := entities.User{
					PublicID: publicID,
					Name:     name,
					UsingIOT: usingIOT,
				}

				users = append(users, user)
			}
		}
		return users, nil
	}
}

//Function for adding user to db during registration
func (userModel UserModel) RegisterUser(name, email, password, q1, q2, q3, a1, a2, a3 string) (user []entities.User) {
	randomID := uuid.New().String()
	var users []entities.User
	rows, err := userModel.Db.Prepare("insert into user (public_id, name, email, password, using_iot, Question_1, Question_2, Question_3, Answer_1, Answer_2, Answer_3) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {

		fmt.Println(err)

	} else {

		iotVal := false
		rows.Exec(randomID, name, email, password, iotVal, q1, q2, q3, a1, a2, a3)
		newUser := entities.User{
			Name:      name,
			PublicID:  randomID,
			UsingIOT:  iotVal,
			Question1: q1,
			Question2: q2,
			Question3: q3,
		}

		users = append(users, newUser)

		return users
	}

	return users
}

//function for determing if user exists in db
func (userModel UserModel) VerifyUser(name, password string) (user []entities.UserWithPassword, err error) {

	rows, err := userModel.Db.Query("select * from user where name = ?", name)
	fmt.Println(rows)
	if err != nil {
		return nil, err
	} else {
		var users []entities.UserWithPassword
		for rows.Next() {
			var id int64
			var publicID string
			var nameuser string
			var emailuser string
			var passworduser string
			var usingIOT bool
			var secQ1 string
			var secQ2 string
			var secQ3 string
			var secA1 string
			var secA2 string
			var secA3 string

			scanErr := rows.Scan(&id, &publicID, &nameuser, &emailuser, &passworduser, &usingIOT, &secQ1, &secQ2, &secQ3, &secA1, &secA2, &secA3)

			if scanErr != nil {
				return nil, scanErr
			} else {
				user := entities.UserWithPassword{
					Name:      nameuser,
					Password:  passworduser,
					Email:     emailuser,
					PublicID:  publicID,
					UsingIOT:  usingIOT,
					Question1: secQ1,
					Question2: secQ2,
					Question3: secQ3,
				}

				users = append(users, user)

				compareHashErr := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))

				if compareHashErr != nil && compareHashErr == bcrypt.ErrMismatchedHashAndPassword {
					return nil, compareHashErr
				}

			}

		}

		return users, nil

	}

}

//Function for returning user email
func (userModel UserModel) VerifyEmail(email string) (user []entities.ForgotPassword, err error) {
	rows, err := userModel.Db.Query("select email from user where email = ?", email)
	if err != nil {
		return nil, err
	} else {
		var users []entities.ForgotPassword
		for rows.Next() {

			var email string

			scanErr := rows.Scan(&email)

			if scanErr != nil {
				return nil, scanErr
			} else {
				user := entities.ForgotPassword{
					Email: email,
				}

				users = append(users, user)
			}
		}
		return users, nil
	}
}

//Function for getting users securtiy questions givne user email
func (userModel UserModel) GetSecurityQuestions(email string) (user []entities.SecurityQuestion, err error) {
	rows, err := userModel.Db.Query("select Question_1, Question_2, Question_3 from user where email = ?", email)
	if err != nil {
		return nil, err
	} else {
		var users []entities.SecurityQuestion
		for rows.Next() {

			var Q1 string
			var Q2 string
			var Q3 string

			scanErr := rows.Scan(&Q1, &Q2, &Q3)

			if scanErr != nil {
				return nil, scanErr
			} else {
				user := entities.SecurityQuestion{
					SecQues1: Q1,
					SecQues2: Q2,
					SecQues3: Q3,
				}

				users = append(users, user)
			}
		}
		return users, nil
	}
}

//Function for getting user security questions with user public_id
func (userModel UserModel) GetSecurityQuestionsPubID(public_id string) (user []entities.SecurityQuestion, err error) {
	rows, err := userModel.Db.Query("select Question_1, Question_2, Question_3 from user where public_id = ?", public_id)
	if err != nil {
		return nil, err
	} else {
		var users []entities.SecurityQuestion
		for rows.Next() {

			var Q1 string
			var Q2 string
			var Q3 string

			scanErr := rows.Scan(&Q1, &Q2, &Q3)

			if scanErr != nil {
				return nil, scanErr
			} else {
				user := entities.SecurityQuestion{
					SecQues1: Q1,
					SecQues2: Q2,
					SecQues3: Q3,
				}

				users = append(users, user)
			}
		}
		return users, nil
	}
}

//Function for getting user security answers given email
func (userModel UserModel) GetSecurityAnswers(email string) (user []entities.SecurityAnswer, err error) {
	rows, err := userModel.Db.Query("select Answer_1, Answer_2, Answer_3 from user where email = ?", email)
	if err != nil {
		return nil, err
	} else {
		var users []entities.SecurityAnswer
		for rows.Next() {

			var A1 string
			var A2 string
			var A3 string

			scanErr := rows.Scan(&A1, &A2, &A3)

			if scanErr != nil {
				return nil, scanErr
			} else {
				user := entities.SecurityAnswer{
					Ans1: A1,
					Ans2: A2,
					Ans3: A3,
				}

				users = append(users, user)
			}
		}
		return users, nil
	}
}

//Grab user email given public_id
func (userModel UserModel) GetEmail(public_id string) (user []entities.ForgotPassword, err error) {
	rows, err := userModel.Db.Query("select email from user where public_id = ?", public_id)
	if err != nil {
		return nil, err
	} else {
		var users []entities.ForgotPassword
		for rows.Next() {

			var email string

			scanErr := rows.Scan(&email)

			if scanErr != nil {
				return nil, scanErr
			} else {
				user := entities.ForgotPassword{
					Email: email,
				}

				users = append(users, user)
			}
		}
		return users, nil
	}
}

//Updating user password in db
func (userModel UserModel) UpdatePassword(password, email string) (succ string) {

	rows, err := userModel.Db.Prepare("update user set password = ? where email = ?")

	if err != nil {
		fmt.Println(err)
	} else {

		rows.Exec(password, email)

	}

	return "Successfully update user password."

}

//Adding user device to db
func (userModel UserModel) AddDevice(name, owner_pub_id string) (device_public_id string) {
	randomID := uuid.New().String()
	msg := " "
	getID, idErr := userModel.Db.Query("select id from user where public_id = ?", owner_pub_id)

	if idErr != nil {
		fmt.Println("Owner ID lookup error")
	} else {

		var device []entities.Device

		for getID.Next() {
			var id int64

			idScan := getID.Scan(&id)

			newDevice := entities.Device{
				Name: name,
			}

			if idScan != nil {
				fmt.Println("error")
			} else {

				rows, err := userModel.Db.Prepare("insert into device (public_id, name, owner_id, is_verified) values (?, ?, ?, ?)")

				if err != nil {
					fmt.Println("Error adding device")
				} else {
					isVerified := false
					rows.Exec(randomID, name, id, isVerified)

					device := append(device, newDevice)

					iotVal := true

					updateIOT, iotErr := userModel.Db.Prepare("update user set using_iot = ? where id = ?")

					if iotErr != nil {
						fmt.Println("Error updating iot val")
					} else {
						updateIOT.Exec(iotVal, id)
						fmt.Println("Updated iot value")

					}

					if device != nil {
						return randomID
					} else {
						fmt.Println("error")
					}

				}
			}

		}

	}
	return msg
}

//Verifying user device
func (userModel UserModel) VerifyDevice(public_id, device_public_id string) (succ string) {

	getID, idErr := userModel.Db.Query("select id from user where public_id = ?", public_id)
	defaultReturn := " "

	if idErr != nil {
		fmt.Println("Error getting user id")
	} else {
		for getID.Next() {
			var id int64

			idScan := getID.Scan(&id)

			if idScan != nil {
				fmt.Println("Error")
			} else {
				isVerified, verErr := userModel.Db.Prepare("update device set is_verified = ?, verified_date = now() where owner_id =? and public_id = ?")

				if verErr != nil {
					fmt.Println("Error updating verification value")
				} else {
					verification := true

					isVerified.Exec(verification, id, device_public_id)

					msg := "Successfully verified"

					return msg
				}
			}

		}
	}
	return defaultReturn
}

//Checking if device is verified
func (userModel UserModel) IsDeviceVerified(public_id string) (succ string) {
	getID, idErr := userModel.Db.Query("select id from user where public_id = ?", public_id)
	defaultReturn := ""
	if idErr != nil {
		fmt.Println("Error getting user id")
	} else {
		for getID.Next() {
			var id int64

			idScan := getID.Scan(&id)

			if idScan != nil {
				fmt.Println("Error")
			} else {
				isVerified, verErr := userModel.Db.Query("select is_verified from device where owner_id = ?", id)

				if verErr != nil {
					fmt.Println("Error checking is verified value")
				} else {
					for isVerified.Next() {
						var is_verified bool

						isVer := isVerified.Scan(&is_verified)

						if isVer != nil {
							fmt.Print("Error scanning ")
						} else {
							return strconv.FormatBool(is_verified)
						}
					}
				}
			}

		}
	}
	return defaultReturn
}

//Queries db for all user devices
func (userModel UserModel) GetAllDevices(public_id string) (device []entities.AllDevice) {

	getID, idErr := userModel.Db.Query("select id from user where public_id = ?", public_id)
	var devices []entities.AllDevice
	if idErr != nil {
		fmt.Println("Error getting user id")
	} else {
		for getID.Next() {
			var id int64

			idScan := getID.Scan(&id)

			if idScan != nil {
				fmt.Println("Error")
			} else {

				allDevices, devErr := userModel.Db.Query("select * from device where owner_id = ?", id)

				if devErr != nil {
					fmt.Println("Error checking is verified value")
				} else {

					for allDevices.Next() {
						var devID int64
						var ownerID int64
						var name string
						var pubID string
						var isVer bool

						devScan := allDevices.Scan(&devID, &ownerID, &name, &pubID, &isVer)

						if devScan != nil {
							fmt.Print("Error")
						} else {

							newDevice := entities.AllDevice{
								PublicID:   pubID,
								Name:       name,
								IsVerified: isVer,
							}

							devices := append(devices, newDevice)

							return devices
						}

					}
				}
			}

		}
	}
	return devices
}
