package main

import (
	"fmt"
	"strconv"
	"strings"

	"go.riyazali.net/sqlite"

	"github.com/leekchan/accounting"
)

// Upper implements a custom Upper(...) scalar sql function
type Upper struct{}

func (m *Upper) Args() int           { return 1 }
func (m *Upper) Deterministic() bool { return true }
func (m *Upper) Apply(ctx *sqlite.Context, values ...sqlite.Value) {
	fmt.Println(len(values))
	a := "AA"
	ctx.ResultText(values[0].Text() + a + strings.ToUpper(values[1].Text()))
}

type Money struct{}

func (m *Money) Args() int           { return 2 }
func (m *Money) Deterministic() bool { return true }
func (m *Money) Apply(ctx *sqlite.Context, values ...sqlite.Value) {
	money, err := strconv.ParseFloat(values[1].Text(), 64)
	if err != nil {
		ctx.ResultError(err)
		return
	}

	ac := accounting.Accounting{Symbol: values[0].Text(), Precision: 2}
	ctx.ResultText(ac.FormatMoney(money))
}

func init() {
	sqlite.Register(func(api *sqlite.ExtensionApi) (sqlite.ErrorCode, error) {
		if err := api.CreateFunction("upper", &Upper{}); err != nil {
			return sqlite.SQLITE_ERROR, err
		}

		if err := api.CreateFunction("Money", &Money{}); err != nil {
			return sqlite.SQLITE_ERROR, err
		}

		// AES functions
		if err := api.CreateFunction("aes_encrypt", &aes_encrypt{}); err != nil {
			return sqlite.SQLITE_ERROR, err
		}
		if err := api.CreateFunction("aes_decrypt", &aes_decrypt{}); err != nil {
			return sqlite.SQLITE_ERROR, err
		}
		if err := api.CreateFunction("generate_aes256_key", &generate_aes256_key{}); err != nil {
			return sqlite.SQLITE_ERROR, err
		}
		if err := api.CreateFunction("sha512", &sha512{}); err != nil {
			return sqlite.SQLITE_ERROR, err
		}
		if err := api.CreateFunction("sha512_fixed_length", &sha512_fixed_length{}); err != nil {
			return sqlite.SQLITE_ERROR, err
		}

		fmt.Println("SIGNAL ZERO EXTENSIONS LOADED.")
		return sqlite.SQLITE_OK, nil
	})
}

func main() {}
