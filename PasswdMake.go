package main

import (
	"encoding/base64"
	"fmt"
	"math"
	"os"
	"path"
	"strconv"
	"strings"
)

var secretstr = "!pqr$*+STU%Vstuv:w'{WX&YZ-Q_r$*/02.3(4Al<BCo|xy8X&YjDE^FG?IH[]JK>LM#N6mnz}OP);Ra@bce7d=9fg5hi,k1mnz}"

func HashMn(seed string) float64 {
	hashvalue := 0
	for i, c := range []rune(seed) {
		hashvalue += (i + 1) * int(c)
	}

	res := math.Pow(float64(hashvalue%127), float64(3)) - 1
	if res == 0 {
		res = float64(8191*2) + float64(hashvalue)
	}

	return res
}

func stringReverse(str string) string {
	bytes := []byte(str)

	for i := 0; i < len(bytes)/2; i++ {
		tmp := bytes[len(bytes)-i-1]
		bytes[len(bytes)-i-1] = bytes[i]
		bytes[i] = tmp
	}

	return string(bytes)
}

func HashPassword(seed string, bit int) string {
	ctrlkey := map[string]int{
		"minseedLen": 4,
		"trunctLen":  2,
		"minpswdLen": 6,
		"maxpswdLen": 20,
	}
	length := map[string]int{
		"6": 1, "7": 1, "8": 1, "9": 1, "10": 1,
		"11": 2, "12": 2, "13": 2, "14": 2, "15": 2,
		"16": 3, "17": 3, "18": 3, "19": 3, "20": 3,
	}

	if len(seed) < ctrlkey["minseedLen"] {
		fmt.Printf("seed = %s must have length >= 4\n", seed)
		os.Exit(1)
	}

	if !(ctrlkey["maxpswdLen"] >= bit && bit >= ctrlkey["minpswdLen"]) {
		fmt.Println("password length must in 6-20")
		os.Exit(1)
	}

	hashvalue := HashMn(seed)
	hashstr := strconv.Itoa(int(math.Pow(hashvalue, float64(length[strconv.Itoa(bit)]))))
	if len(hashstr)%2 != 0 {
		hashstr = hashstr[:len(hashstr)-1]
	}

	passwd := ""
	for {
		if len(hashstr) == 0 {
			break
		}

		pos, _ := strconv.Atoi(hashstr[:ctrlkey["trunctLen"]])

		if pos >= len(secretstr) {
			pos = pos % len(secretstr)
		}

		passwd += string(secretstr[pos])
		hashstr = hashstr[ctrlkey["trunctLen"]:]
	}

	passwd = strings.Join([]string{passwd}, seed)
	passwd = base64.StdEncoding.EncodeToString([]byte(passwd))
	passwd = strings.Replace(passwd, "+", "*", -1)
	passwd = strings.Replace(passwd, "/", "#", -1)
	passwd = strings.Replace(passwd, "=", "*", -1)

	for {
		if len(passwd) >= bit {
			break
		}
		passwd += stringReverse(passwd)
	}

	passwd = seed + ": " + passwd[:bit]

	return passwd
}

func main() {
	var seed string
	var length int

	if len(os.Args) == 3 {
		leng, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		length = leng
	} else if len(os.Args) == 2 {
		length = 16
	} else {
		fmt.Printf("Usage: %s seed [length]\n", path.Base(os.Args[0]))
		os.Exit(1)
	}

	seed = os.Args[1]
	fmt.Println(HashPassword(seed, length))
}
