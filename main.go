// create table app_users( user_id int auto_increment, user_name varchar(40) not null, mail_address varchar(100) not null unique, password_hash varbinary(100), salt varbinary(20) not null, primary key(user_id));
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	PORT   = "4201"
	SECRET = "42isTheAnswer"
)

var db = &sql.DB{}

func main() {

	var err error
	db, err = sql.Open("mysql", "root:qwertyui@tcp(127.0.0.1:3306)/old_book")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.SetMaxIdleConns(20)
	db.SetMaxOpenConns(20)

	if err := db.Ping(); err != nil {
		log.Fatalln(err)
		return
	}

	engine := gin.Default()
	engine.Any("/login", Login)
	engine.Any("signup", Signup)
	engine.GET("/getbook/:arg", GetBook)
	engine.Run(":4201")

	/*
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Println(err)
			http.Error(w, "Login failed!", http.StatusUnauthorized)
			return
		}

		var userData map[string]string
		json.Unmarshal(body, &userData)

		var password_hash string
		var salt string
		// verify the input
		err = db.QueryRow("select password_hash, salt from app_users where mail_address = ?",
			userData["email"]).Scan(&password_hash, &salt)
		if err != nil {
			log.Println(err)
			http.Error(w, "login failed!", http.StatusUnauthorized)
			return
		}

		// check the password
		sha := sha256.New()
		sha.Write(append([]byte(salt), userData["password"]...))
		sha_result := sha.Sum([]byte(""))
		fmt.Println("sha", sha_result)

		if strings.Compare(string(sha_result), password_hash) != 0 {
			log.Println(err)
			http.Error(w, "login failed!", http.StatusUnauthorized)
			return
		}

		fmt.Println("into right branch.")

		// calculate the JWT
		claims := JWTData{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			},
			CustomClaims: map[string]string{
				"userid": "zuhxs",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(SECRET))
		if err != nil {
			log.Println(err)
			http.Error(w, "Login failed!", http.StatusUnauthorized)
			return
		}

		json, err := json.Marshal(struct {
			Token string `json:"token"`
		}{
			tokenString,
		})

		if err != nil {
			log.Println(err)
			http.Error(w, "login failed!", http.StatusUnauthorized)
			return
		}

		w.Write(json)
	})

	// username, email, password
	mux.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Println(err)
			http.Error(w, "Login failed!", http.StatusUnauthorized)
			return
		}

		var userData map[string]string
		json.Unmarshal(body, &userData)

		// first generate seed
		seed := make([]byte, 20)
		if _, err := io.ReadFull(rand.Reader, seed); err != nil {
			log.Println(err)
			return
		}
		fmt.Println("seed", seed)

		// calculate hash
		sha := sha256.New()
		sha.Write(append(seed[:], userData["password"]...))
		sha_result := sha.Sum([]byte(""))
		fmt.Println("sha", sha_result)

		_, err = db.Exec("INSERT INTO app_users(user_name, mail_address, password_hash, salt) values (?, ?, ?, ?)",
			userData["username"], userData["email"], sha_result, seed)
		if err != nil {
			log.Fatalln(err)
			http.Error(w,"Username does not exist!", http.StatusUnauthorized)
			return
		}

		// begin to write JWT
		claims := JWTData{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			},
			CustomClaims: map[string]string{
				"userid": userData["username"],
				"email": userData["email"],
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(SECRET))
		if err != nil {
			log.Println(err)
			http.Error(w, "Login failed!", http.StatusUnauthorized)
			return
		}

		json, err := json.Marshal(struct {
			Token string `json:"token"`
		}{
			tokenString,
		})

		if err != nil {
			log.Println(err)
			http.Error(w, "login failed!", http.StatusUnauthorized)
			return
		}

		w.Write(json)

	})

	mux.HandleFunc("/getbook/{request}", func(w http.ResponseWriter, r *http.Request){
	})

	handler := cors.Default().Handler(mux)
	log.Println("Listening for connections on port: ", PORT)
	log.Fatal(http.ListenAndServe(":"+PORT, handler))
	*/
}



func WebRoot(context *gin.Context) {
	context.String(http.StatusOK, "hello, world")
}

func GetBook(context *gin.Context) {
	arg := context.Param("arg")
	fmt.Println(arg)
}

func Login(context *gin.Context) {
	context.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	body, err := ioutil.ReadAll(context.Request.Body)
	if err != nil {
		log.Println(err)
		http.Error(context.Writer, "Login failed!", http.StatusUnauthorized)
		return
	}

	var userData map[string]string
	json.Unmarshal(body, &userData)

	var password_hash string
	var salt string
	// verify the input
	err = db.QueryRow("select password_hash, salt from app_users where mail_address = ?",
		userData["email"]).Scan(&password_hash, &salt)
	if err != nil {
		log.Println(err)
		http.Error(context.Writer, "login failed!", http.StatusUnauthorized)
		return
	}

	// check the password
	sha := sha256.New()
	sha.Write(append([]byte(salt), userData["password"]...))
	sha_result := sha.Sum([]byte(""))
	fmt.Println("sha", sha_result)

	if strings.Compare(string(sha_result), password_hash) != 0 {
		log.Println(err)
		http.Error(context.Writer, "login failed!", http.StatusUnauthorized)
		return
	}

	fmt.Println("into right branch.")

	// calculate the JWT
	claims := JWTData{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
		CustomClaims: map[string]string{
			"userid": "zuhxs",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(SECRET))
	if err != nil {
		log.Println(err)
		http.Error(context.Writer, "Login failed!", http.StatusUnauthorized)
		return
	}

	json, err := json.Marshal(struct {
		Token string `json:"token"`
	}{
		tokenString,
	})

	if err != nil {
		log.Println(err)
		http.Error(context.Writer, "login failed!", http.StatusUnauthorized)
		return
	}

	context.Writer.Write(json)
}

func Signup(context *gin.Context) {
	w := context.Writer
	r := context.Request
	w.Header().Set("Access-Control-Allow-Origin", "*")
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, "Login failed!", http.StatusUnauthorized)
		return
	}

	var userData map[string]string
	json.Unmarshal(body, &userData)

	// first generate seed
	seed := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		log.Println(err)
		return
	}
	fmt.Println("seed", seed)

	// calculate hash
	sha := sha256.New()
	sha.Write(append(seed[:], userData["password"]...))
	sha_result := sha.Sum([]byte(""))
	fmt.Println("sha", sha_result)

	_, err = db.Exec("INSERT INTO app_users(user_name, mail_address, password_hash, salt) values (?, ?, ?, ?)",
		userData["username"], userData["email"], sha_result, seed)
	if err != nil {
		log.Fatalln(err)
		http.Error(w,"Username does not exist!", http.StatusUnauthorized)
		return
	}

	// begin to write JWT
	claims := JWTData{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
		CustomClaims: map[string]string{
			"userid": userData["username"],
			"email": userData["email"],
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(SECRET))
	if err != nil {
		log.Println(err)
		http.Error(w, "Login failed!", http.StatusUnauthorized)
		return
	}

	json, err := json.Marshal(struct {
		Token string `json:"token"`
	}{
		tokenString,
	})

	if err != nil {
		log.Println(err)
		http.Error(w, "login failed!", http.StatusUnauthorized)
		return
	}

	w.Write(json)
}

type JWTData struct {
	jwt.StandardClaims
	CustomClaims map[string]string `json:"custom,omitempty"`
}

func login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, "Login failed!", http.StatusUnauthorized)
	}

	var userData map[string]string
	json.Unmarshal(body, &userData)

	if userData["email"] == "zuhxs@berkeley.edu" && userData["password"] == "admin123" {
		claims := JWTData{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			},
			CustomClaims: map[string]string{
				"userid": "zuhxs",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(SECRET))
		if err != nil {
			log.Println(err)
			http.Error(w, "Login failed!", http.StatusUnauthorized)
		}

		json, err := json.Marshal(struct {
			Token string `json:"token"`
		}{
			tokenString,
		})

		if err != nil {
			log.Println(err)
			http.Error(w, "login failed!", http.StatusUnauthorized)
		}

		w.Write(json)
	} else {
		http.Error(w, "Login failed!", http.StatusUnauthorized)
	}
}