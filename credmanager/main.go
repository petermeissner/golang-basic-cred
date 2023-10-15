package main

import (
	"fmt"

	"github.com/glebarez/sqlite"
	. "github.com/petermeissner/golang-basic-cred/golang-basic-cred"
	"gorm.io/gorm"
)

// try it out
func main() {

	// establish db connection
	gorm_dialect := sqlite.Open("gorm.db")
	db, err := gorm.Open(gorm_dialect, &gorm.Config{})
	Log_if_fatal(err)

	// user selection on task to do
	menu_string := "\n(1) add/update credential" +
		"\n(2) check credential" +
		"\n(3) list credentials\n"

	for {
		menu := Get_input(menu_string)
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
			Pretty_print(res)

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
			Pretty_print(res)

		default:
		}

		// reset selection
		menu = ""
	}

}
