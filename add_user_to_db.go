package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func log_if_fatal(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

// Credential type
//
// with hashed password after adding salt and pepper
type Credential struct {
	Username string
	Salt     string
	Hash     string
}

// Credential type
//
// with hashed password after adding salt and pepper
// ready to be put in DB
type CredentialSQL struct {
	gorm.Model
	Username string `gorm:"unique"`
	Salt     string
	Hash     string
}

// Credential type
//
// with raw input
type Auth struct {
	Username string
	Password string
}

const BCRYPT_DEFAULT_COST = bcrypt.DefaultCost + 4

// # str_random
//
// produce string of random characters of length n
func str_random(n int) string {
	rand.Seed(time.Now().UnixNano())
	letterRunes := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!§$%&/()=?+*'#,;.:-_")
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// MakeCredential
//
// generates a credential from username, password and pepper
func Make_credential(username string, password string, pepper string) Credential {

	// generate random salt
	salt := str_random(20)

	// salt and pepper pw then hash it
	pw_hash := Hash_SaltPepper_Password(password, salt, pepper)

	// return
	cred := Credential{
		Username: username,
		Salt:     salt,
		Hash:     string(pw_hash),
	}
	return cred
}

func Hash_SaltPepper_Password(password string, salt string, pepper string) []byte {
	salted_pw := password + salt + pepper
	pw_hash, err := bcrypt.GenerateFromPassword([]byte(salted_pw), BCRYPT_DEFAULT_COST)
	if err != nil {
		panic(err)
	}
	return pw_hash
}

// MakeCredentialSQL
//
// generates a credential from username, password and pepper
func Make_credential_sql(username string, password string, pepper string) CredentialSQL {
	cred := Make_credential(username, password, pepper)
	return CredentialSQL{Username: cred.Username, Hash: cred.Hash, Salt: cred.Salt}
}

// Function to read in pepper
//
// looks for config file or creates one
func Create_read_pepper() string {
	fname := "pw.conf"
	pepper := ""

	_, err := os.Stat(fname)
	if err != nil {

		host, err := os.Hostname()
		log_if_fatal(err)
		pepper = host + "-" + str_random(12)
		err = os.WriteFile(fname, []byte(pepper), 0600)
		log_if_fatal(err)

	} else {

		tmp, err := os.ReadFile(fname)
		pepper = string(tmp)
		log_if_fatal(err)

	}

	return pepper
}

func get_input(prompt string) string {

	r := bufio.NewReader(os.Stdin)

	fmt.Print(prompt)
	text, _ := r.ReadString('\n')

	// remove line endings from input string
	text = strings.Replace(text, "\n", "", -1)
	text = strings.Replace(text, "\r", "", -1)

	return text
}

// Function for printing Objects
//
// prints any object (as JSON)
// as long as it can be serialized to JSON
func pretty_print(obj any) {
	enc, err := json.MarshalIndent(obj, "", "  ")
	log_if_fatal(err)
	fmt.Println(string(enc))
}

// Function to retrieve name/password from terminal
//
// - will prompt for user input and
// - will hide password input in terminal
func Get_auth_from_term() Auth {
	// get credentials
	username := get_input("Enter user name:")
	fmt.Print("Enter password: ")
	pw, err := term.ReadPassword(int(syscall.Stdin))
	log_if_fatal(err)

	return Auth{Username: username, Password: string(pw)}
}

func Upsert_auth_as_credential_to_db(db *gorm.DB, auth Auth) CredentialSQL {
	// prepare data for database
	p := Create_read_pepper()
	cred := Make_credential_sql(auth.Username, auth.Password, p)

	// store in db
	db.AutoMigrate(&CredentialSQL{})
	db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "username"}},
		DoUpdates: clause.AssignmentColumns([]string{"salt", "hash"}),
	}).Create(&cred)

	var res CredentialSQL
	db.Where("Username = ?", cred.Username).Find(&CredentialSQL{}).Scan(&res)
	return res
}

func Check_credential(db *gorm.DB, auth Auth) bool {

	var cred CredentialSQL
	db.Where("Username = ?", auth.Username).First(&CredentialSQL{}).Scan(&cred)

	// salt and pepper pw then hash it
	pepper := Create_read_pepper()
	salted_pw := auth.Password + cred.Salt + pepper
	err := bcrypt.CompareHashAndPassword([]byte(cred.Hash), []byte(salted_pw))
	if err != nil {
		return false
	} else {
		return true
	}
}

// try it out
func main() {

	// establish db connection
	gorm_dialect := sqlite.Open("gorm.db")
	db, err := gorm.Open(gorm_dialect, &gorm.Config{})
	log_if_fatal(err)

	// user selection on task to do
	menu_string := "\n(1) add/update credential" +
		"\n(2) check credential" +
		"\n(3) list credentials\n"

	for {
		menu := get_input(menu_string)
		switch menu {

		case "1":
			// get authentication info
			auth := Get_auth_from_term()

			// Hash credentials and store them in db
			Upsert_auth_as_credential_to_db(db, auth)

			// check results
			var res []CredentialSQL
			db.Find(&res)
			fmt.Println("\nAll entries ... N = ", len(res))

			db.Where("Username = ?", auth.Username).Find(&CredentialSQL{}).Scan(&res)
			fmt.Println("\nCurrent entry ... ")
			pretty_print(res)

		case "2":
			// get authentication info
			auth := Get_auth_from_term()

			is_ok := Check_credential(db, auth)
			if is_ok {
				fmt.Println("Check OK")
			} else {
				fmt.Println("Check FAILED")
			}

		case "3":
			// get all credentials
			var res []CredentialSQL
			db.Find(&res)
			pretty_print(res)

		default:
		}

		// reset selection
		menu = ""
	}

}
