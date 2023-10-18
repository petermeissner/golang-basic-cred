package pkg

import "gorm.io/gorm"

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
