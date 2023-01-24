package main

import (
	"testing"
	"time"

	. "github.com/petermeissner/golang-basic-cred/library"
	"golang.org/x/crypto/bcrypt"
)

const BCRYPT_TEST_COSTS = 0

func Test_basic_hashing_bcrypt(t *testing.T) {
	pw1 := "ohmei"
	hash_1, err := bcrypt.GenerateFromPassword([]byte(pw1), BCRYPT_TEST_COSTS)
	if err != nil {
		panic(err)
	}

	matching_pw1 := bcrypt.CompareHashAndPassword(hash_1, []byte(pw1))
	if matching_pw1 != nil {
		t.Error("PW-Hash-Comparison failed", matching_pw1.Error())
	}

	pw2 := "ohmei"
	hash_2, err := bcrypt.GenerateFromPassword([]byte(pw2), BCRYPT_TEST_COSTS)
	if err != nil {
		panic(err)
	}

	matching_pw2 := bcrypt.CompareHashAndPassword(hash_2, []byte(pw1))
	if matching_pw2 != nil {
		t.Error("PW-Hash-Comparison failed", matching_pw2.Error())
	}

	matching_pw3 := bcrypt.CompareHashAndPassword(hash_2, []byte("wtf"))
	if matching_pw3 == nil {
		t.Error("PW-Hash-Comparison failed", matching_pw2.Error())
	}

}

func Test_basic_hashing_pepper(t *testing.T) {
	pw1 := "ohmei"
	hash_1, err := bcrypt.GenerateFromPassword([]byte(pw1), BCRYPT_TEST_COSTS)
	if err != nil {
		panic(err)
	}

	matching_pw1 := bcrypt.CompareHashAndPassword(hash_1, []byte(pw1))
	if matching_pw1 != nil {
		t.Error("PW-Hash-Comparison failed", matching_pw1.Error())
	}

	pw2 := "ohmei"
	hash_2, err := bcrypt.GenerateFromPassword([]byte(pw2), BCRYPT_TEST_COSTS)
	if err != nil {
		panic(err)
	}

	matching_pw2 := bcrypt.CompareHashAndPassword(hash_2, []byte(pw1))
	if matching_pw2 != nil {
		t.Error("PW-Hash-Comparison failed", matching_pw2.Error())
	}
}

func Test_basic_hashing(t *testing.T) {
	slt := Str_random(14)

	pw1 := "ohmei"
	ppr1 := Create_read_pepper()
	hash_1 := Hash_SaltPepper_Password(pw1, slt, ppr1)

	pw2 := "ohmei"
	ppr2 := Create_read_pepper()
	hash_2 := Hash_SaltPepper_Password(pw2, slt, ppr2)

	matching_pw1 := bcrypt.CompareHashAndPassword(hash_1, []byte(pw1+slt+ppr1))
	if matching_pw1 != nil {
		t.Log(matching_pw1)
		t.Error("No match")
	}

	matching_pw2 := bcrypt.CompareHashAndPassword(hash_2, []byte(pw1+slt+ppr1))
	if matching_pw2 != nil {
		t.Log(matching_pw2)
		t.Error("No match")
	}

}

func Test_time_for_hashing(t *testing.T) {

	pw1 := "öoashfglkysdfvlkbweuifin"
	start := time.Now()
	hash, err := bcrypt.GenerateFromPassword([]byte(pw1), BCRYPT_DEFAULT_COST)
	if err != nil {
		panic(err)
	}
	elapsed := time.Since(start)

	t.Log(elapsed)

	// check test condition
	et := time.Duration(0.5 * 1000 * time.Millisecond)
	t.Log("elapsed: ", elapsed, "minimum execution time: ", et)
	if elapsed < et {
		t.Error("PW-Hashing execution time was not ok:", "!(", elapsed, "<", et, ")")
	}

	matching := bcrypt.CompareHashAndPassword(hash, []byte(pw1))
	if matching != nil {
		t.Error("PW-Hash-Comparison failed", matching.Error())
	}
}
