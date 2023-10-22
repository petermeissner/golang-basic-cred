package pkg

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
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func Log_if_fatal(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

// # str_random
//
// produce string of random characters of length n
func Str_random(n int) string {
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
	salt := Str_random(20)

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
func Create_read_pepper(fname string) string {
	pepper := ""

	_, err := os.Stat(fname)
	if err != nil {

		host, err := os.Hostname()
		Log_if_fatal(err)
		pepper = host + "-" + Str_random(12)
		err = os.WriteFile(fname, []byte(pepper), 0600)
		Log_if_fatal(err)

	} else {

		tmp, err := os.ReadFile(fname)
		pepper = string(tmp)
		Log_if_fatal(err)

	}

	return pepper
}

func Get_input(prompt string) string {

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
func Pretty_print(obj any) {
	enc, err := json.MarshalIndent(obj, "", "  ")
	Log_if_fatal(err)
	fmt.Println(string(enc))
}

// Function to retrieve name/password from terminal
//
// - will prompt for user input and
// - will hide password input in terminal
func Get_auth_from_term() Auth {
	// get credentials
	username := Get_input("Enter user name:")
	fmt.Print("Enter password: ")
	pw, err := term.ReadPassword(int(syscall.Stdin))
	Log_if_fatal(err)

	return Auth{Username: username, Password: string(pw)}
}

func Upsert_auth_as_credential_to_db(db *gorm.DB, config_file string, auth Auth) CredentialSQL {
	// prepare data for database
	p := Create_read_pepper(config_file)
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

func Check_credential(db *gorm.DB, config_file string, auth Auth) bool {

	var cred CredentialSQL
	db.Where("Username = ?", auth.Username).First(&CredentialSQL{}).Scan(&cred)

	// salt and pepper pw then hash it
	pepper := Create_read_pepper(config_file)
	salted_pw := auth.Password + cred.Salt + pepper
	err := bcrypt.CompareHashAndPassword([]byte(cred.Hash), []byte(salted_pw))
	if err != nil {
		return false
	} else {
		return true
	}
}
