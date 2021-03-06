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

// 密码字符串映射表，可随意打乱次序和增删
var secretStr = "!prq*$+ST%UVstuv:w{W&XYZ-/_013.42<ABo|CxyDE^F?HIG[/]JK>LMN#OP;QRab@cd5e68=79fg,hjmk1niz}"

// 控制密码生成
var ctrlKey = map[string]int{
	"minseedLen": 4,
	"minpswdLen": 6,
	"maxpswdLen": 20,
}

// 控制密码长度
var passLength = map[string]int{
	"6":  1,"7":  1,"8":  1,"9":  1,"10": 1,
    "11": 2,"12": 2,"13": 2,"14": 2,"15": 2,
	"16": 3,"17": 3,"18": 3,"19": 3,"20": 3,
}

// 用梅森素数[3,7,31,127,8191,131071,524287]求哈希
func HashMn(seed string) (res float64) {
	hashval := 0
	for i, c := range []byte(seed) {
		hashval += (i + 1) * int(c)
	}

	res = math.Pow(float64(hashval % 127), 3) - 1
	if res == 0 {
		res = float64(hashval) + float64(2 * 8191)
	}

	return
}

// 字符串翻转
func reverseString(str string) (revertStr string) {
	bytes := []byte(str)
    byteLen := len(bytes)
	for i := 0; i < byteLen/2; i++ {
		bytes[byteLen-i-1], bytes[i] = bytes[i], bytes[byteLen-i-1]
	}
    revertStr = string(bytes)

	return
}

// 字符串道字符数组
func str2array(str string) (array []string) {
    //array := []string{}
    for _, s := range str {
        array = append(array, string(s))
    }
    return
}

// 参数检查
func checkParams(seed string, bit int) {
	if len(seed) < ctrlKey["minseedLen"] {
		fmt.Printf("seed = %s must have length >= 4\n", seed)
		os.Exit(1)
	}
	if ! (ctrlKey["maxpswdLen"] >= bit && bit >= ctrlKey["minpswdLen"]) {
		fmt.Println("password length must between 6 and 20")
		os.Exit(1)
	}
}

// 密码生成
func MakePassword(seed string, bit int) (passwd string) {
    checkParams(seed, bit)

	hashval := HashMn(seed)
    order := float64(passLength[strconv.Itoa(bit)])
	hashstr := strconv.Itoa(int(math.Pow(hashval, order)))
	if len(hashstr) % 2 != 0 {
		hashstr = hashstr[:len(hashstr)-1]
	}

	for {
		if hashstr == "" {
			break
		}
		pos, _ := strconv.Atoi(hashstr[:2])
		if pos >= len(secretStr) {
			pos = pos % len(secretStr)
		}
		passwd += string(secretStr[pos])
		hashstr = hashstr[2:]
	}

	passwd = strings.Join(str2array(seed), passwd)
	passwd = base64.StdEncoding.EncodeToString([]byte(passwd))
	for {
		if len(passwd) >= bit {
			break
		}
		passwd += reverseString(passwd)
	}
	passwd = seed + ": " + passwd[:bit]

	return
}

func getSeedPassLen() (seed string, length int) {
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

    return
}

func main() {
    seed, length := getSeedPassLen()
    passwd := MakePassword(seed, length)
	fmt.Println(passwd)
}
