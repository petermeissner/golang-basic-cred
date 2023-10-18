package main

import (
	"fmt"

	"github.com/glebarez/sqlite"
	cred "github.com/petermeissner/golang-basic-cred/pkg"
	"gorm.io/gorm"
)

// try it out
func main() {

	// establish db connection
	gorm_dialect := sqlite.Open("credmanager.db")
	db, err := gorm.Open(gorm_dialect, &gorm.Config{})
	cred.Log_if_fatal(err)

	// ensure tables are set up
	err = db.AutoMigrate(&cred.CredentialSQL{})
	cred.Log_if_fatal(err)

	// user selection on task to do
	menu_string := "\n(1) add/update credential" +
		"\n(2) check credential" +
		"\n(3) list credentials\n"

	for {
		menu := cred.Get_input(menu_string)
		switch menu {

		case "1":
			// get authentication info
			auth := cred.Get_auth_from_term()

			// Hash credentials and store them in db
			cred.Upsert_auth_as_credential_to_db(db, auth)

			// check results
			var res []cred.CredentialSQL
			db.Find(&res)
			fmt.Println("\nAll entries ... N = ", len(res))

			db.Where("Username = ?", auth.Username).Find(&cred.CredentialSQL{}).Scan(&res)
			fmt.Println("\nCurrent entry ... ")
			cred.Pretty_print(res)

		case "2":
			// get authentication info
			auth := cred.Get_auth_from_term()

			is_ok := cred.Check_credential(db, auth)
			if is_ok {
				fmt.Println("Check OK")
			} else {
				fmt.Println("Check FAILED")
			}

		case "3":
			// get all credentials
			var res []cred.CredentialSQL
			db.Find(&res)
			cred.Pretty_print(res)

		default:
		}

		// reset selection
		menu = ""
	}

}
