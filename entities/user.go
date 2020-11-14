package entities

//Creating structs to be used for different endpoints

type User struct {
	PublicID  string `json:"public_id"`
	Name      string `json:"name"`
	Email     string `json:"-"`
	Password  string `json:"-"`
	UsingIOT  bool   `json:"using_iot"`
	Question1 string `json:"Q1"`
	Question2 string `json:"Q2"`
	Question3 string `json:"Q3"`
}

type UserDeviceVer struct {
	PublicID   string `json:"public_id"`
	Name       string `json:"name"`
	Email      string `json:"-"`
	Password   string `json:"-"`
	UsingIOT   bool   `json:"using_iot"`
	Question1  string `json:"Q1"`
	Question2  string `json:"Q2"`
	Question3  string `json:"Q3"`
	IsVerified bool   `json:"is_verified"`
}

type UserWithEmail struct {
	PublicID   string `json:"public_id"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Password   string `json:"-"`
	UsingIOT   bool   `json:"using_iot"`
	Question1  string `json:"Q1"`
	Question2  string `json:"Q2"`
	Question3  string `json:"Q3"`
	IsVerified bool   `json:"is_verified"`
}

type UserWithPassword struct {
	PublicID  string `json:"public_id"`
	Name      string `json:"name"`
	Email     string `json:"-"`
	Password  string `json:"password"`
	UsingIOT  bool   `json:"using_iot"`
	Question1 string `json:"Q1"`
	Question2 string `json:"Q2"`
	Question3 string `json:"Q3"`
}

type UserRegister struct {
	PublicID        string `json:"public_id"`
	Name            string `json:"name"`
	Email           string `json:"email"`
	ConfirmEmail    string `json:"confirm_email"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
	UsingIOT        bool   `json:"using_iot"`
	Question1       string `json:"Q1"`
	Question2       string `json:"Q2"`
	Question3       string `json:"Q3"`
	Answer1         string `json:"A1"`
	Answer2         string `json:"A2"`
	Answer3         string `json:"A3"`
	IOTValue        bool   `json:"using_iot"`
}

type ForgotPassword struct {
	Email string `json:"email"`
}

type SecurityQuestion struct {
	SecQues1 string `json:"Q1"`
	SecQues2 string `json:"Q2"`
	SecQues3 string `json:"Q3"`
}

type ValidQuestions struct {
	Message string
	Q1      string
	Q2      string
	Q3      string
	Q4      string
	Q5      string
	Q6      string
}
type SecurityAnswer struct {
	Ans1 string `json:"A1"`
	Ans2 string `json:"A2"`
	Ans3 string `json:"A3"`
}

type ChangePasswordLink struct {
	Link string `json:"link"`
}

type ResetPassword struct {
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}

type Message struct {
	Message string `json:"message"`
}

type Device struct {
	PublicID string `json:"-"`
	Name     string `json:"name"`
}

type AllDevice struct {
	PublicID   string `json:"public_id"`
	Name       string `json:"name"`
	IsVerified bool   `json:"is_verified"`
}

type VerifyDevice struct{
	PublicID string `json:"public_id"`
}
