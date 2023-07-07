package main

import (
	sha3 "crypto/sha512"
	"encoding/hex"
	"errors"
	"strconv"

	"go.riyazali.net/sqlite"
)

type sha512 struct{}
type sha512_fixed_length struct{}

func (input *sha512) Args() int           { return 1 }
func (input *sha512) Deterministic() bool { return true }
func (input *sha512) Apply(ctx *sqlite.Context, values ...sqlite.Value) {
	hashedValidation := sha3.New()
	hashedValidation.Write([]byte(values[0].Text()))
	ctx.ResultText(hex.EncodeToString(hashedValidation.Sum(nil)))
}

func (input *sha512_fixed_length) Args() int           { return 2 }
func (input *sha512_fixed_length) Deterministic() bool { return true }
func (input *sha512_fixed_length) Apply(ctx *sqlite.Context, values ...sqlite.Value) {

	hashedValidation := sha3.New()
	hashedValidation.Write([]byte(values[0].Text()))

	length, _ := strconv.Atoi(values[1].Text())
	if len(values[1].Text()) == 0 || length < 1 {
		ctx.ResultError(errors.New("please define a length to use in the second parameter"))
		return
	} else {
		length, err := strconv.Atoi(values[1].Text())
		if err != nil {
			ctx.ResultError(err)
			return
		}
		ctx.ResultText(hex.EncodeToString(hashedValidation.Sum(nil))[0:length])
	}
}
