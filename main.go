package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	PORT   = "4201"
	SECRET = "42isTheAnswer"
)

var db = &sql.DB{}

type Book struct {
	BookId string
	PosterId int
	PosterName string
	BookName string
	ExPrice float64
	Price float64
	ISBN string
	ImageURL string
	Date string
	Description string
}

type People struct {
	Userid int
	UserName string
	UserEmail string
}

type Message struct {
	MessageId int
	IfSelfSend bool
	Date string
	Content string
}

type Request struct {
	RequestId int
	UserId string
	UserName string
	Title string
	Content string
	Date string
}

type Order struct {
	OrderId string
	CustomerId string
	CustomerName string
	BookName string
	ExPrice float64
	Price float64
	BookId string
	OrderStatus int
	StartDate string
	EndDate string
}

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
	engine.Any("people/:id", GetPeople)
	engine.POST("message", GetMessage)
	engine.GET("/requests", GetRequest)
	engine.POST("/sendmessage", SendMessage)
	engine.GET("/inprocessorder", InProcessOrder)
	engine.GET("/processedorder", ProcessedOrder)
	engine.GET("/inprocessbooks", InProcessBooks)
	engine.POST("/searchboook", SearchBook)
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


func jwtAuth(token *jwt.Token) (interface{}, error) {
	if jwt.SigningMethodHS256 != token.Method {
		return nil, errors.New("invalid signing algorithm")
	}
	return []byte(SECRET), nil
}

func MakeAuth(authToken string) (userId string, error error) {
	authArr := strings.Split(authToken, " ")
	fmt.Println(authArr)

	if len(authArr) != 2 {
		return "", errors.New("TOKEN not correct, please login again")
	}
	jwtToken := authArr[1]

	claims, err := jwt.ParseWithClaims(jwtToken, &JWTData{}, jwtAuth)

	if err != nil {
		log.Println(err)
		return "", errors.New("TOKEN not correct, please login again")
	}

	data := claims.Claims.(*JWTData)

	userId = data.CustomClaims["userid"]

	return userId, nil
}

func SearchBook(context *gin.Context) {
	context.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	body, err := ioutil.ReadAll(context.Request.Body)
	if err != nil {
		log.Println(err)
		http.Error(context.Writer, "Login failed!", http.StatusUnauthorized)
		return
	}

	var userData map[string]string
	json.Unmarshal(body, &userData)
	rows, err := db.Query("select book_id, name, exprice, price, ISBN, imageURL, date, description" +
		" from books where status = 0 and name like ?", "%" + userData["BookName"] + "%")
	if err != nil {
		log.Println(err)
		http.Error(context.Writer, "Sql Error", http.StatusNotFound)
		return
	}
	var result []Book
	for rows.Next() {
		var bookId int
		var bookName string
		var exPrice float64
		var price float64
		var ISBN string
		var imageURL string
		var date string
		var description string

		if err := rows.Scan(&bookId, &bookName, &exPrice, &price, &ISBN, &imageURL, &date, &description); err != nil {
			log.Println(err)
			http.Error(context.Writer, "Unknown error", http.StatusNotFound)
			return
		}
		result = append(result, Book {BookId: strconv.Itoa(bookId), BookName: bookName, ExPrice: exPrice, Price: price,
			ISBN: ISBN, ImageURL: imageURL, Date: date, Description: description})
	}
	result_marshal, err := json.Marshal(result)
	fmt.Println(string(result_marshal))
	if err != nil {
		log.Fatal(err)
		http.Error(context.Writer, "json error", http.StatusUnauthorized)
		return
	}
	context.Writer.Write(result_marshal)
}

func InProcessBooks(context *gin.Context) {
	context.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	authToken := context.Request.Header.Get("Authorization")
	userEmail, err := MakeAuth(authToken)
	if err != nil {
		http.Error(context.Writer, err.Error(), http.StatusUnauthorized)
		return
	}
	// get user id
	var userId int
	err = db.QueryRow("select user_id from app_users where mail_address = ?",
		userEmail).Scan(&userId)

	rows, err := db.Query("select book_id, name, exprice, price, ISBN, imageURL, date, description from books where posterId = ? and status = 0", userId)
	if err != nil {
		log.Println(err)
		http.Error(context.Writer, "Sql Error, try again", http.StatusNotFound)
		return
	}

	var result []Book
	for rows.Next() {
		var bookId int
		var bookName string
		var exPrice float64
		var price float64
		var ISBN string
		var imageURL string
		var date string
		var description string

		if err := rows.Scan(&bookId, &bookName, &exPrice, &price, &ISBN, &imageURL, &date, &description); err != nil {
			log.Println(err)
			http.Error(context.Writer, "Unknown error", http.StatusNotFound)
			return
		}
		result = append(result, Book {BookId: strconv.Itoa(bookId), BookName: bookName, ExPrice: exPrice, Price: price,
			ISBN: ISBN, ImageURL: imageURL, Date: date, Description: description})
	}
	result_marshal, err := json.Marshal(result)
	fmt.Println(string(result_marshal))
	if err != nil {
		log.Fatal(err)
		http.Error(context.Writer, "json error", http.StatusUnauthorized)
		return
	}
	context.Writer.Write(result_marshal)
}

func ProcessedOrder(context *gin.Context) {
	context.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	// do auth
	authToken := context.Request.Header.Get("Authorization")
	userEmail, err := MakeAuth(authToken)
	if err != nil {
		http.Error(context.Writer, err.Error(), http.StatusUnauthorized)
		return
	}
	// get user id
	var userId int
	err = db.QueryRow("select user_id from app_users where mail_address = ?",
		userEmail).Scan(&userId)

	rows, err := db.Query("select order_id, customer_id, book_id, order_status, start_date, end_date from orders where seller_id = ? and order_status = 2", userId)
	if err != nil {
		log.Println(err)
		http.Error(context.Writer, "Sql Error, try again", http.StatusNotFound)
		return
	}

	var result []Order

	for rows.Next() {
		var orderId int
		var customerId int
		var customerName string
		var bookId int
		var orderStatus int
		var startDate string
		var endDate string
		if err := rows.Scan(&orderId, &customerId, &bookId, &orderStatus, &startDate, &endDate); err != nil {
			log.Println(err)
			http.Error(context.Writer, "Unknown error", http.StatusNotFound)
			return
		}
		// get customer name
		err = db.QueryRow("select user_name from app_users where user_id = ?",
			customerId).Scan(&customerName)
		if err != nil {
			log.Println(err)
			http.Error(context.Writer, "Unknown error", http.StatusNotFound)
			return
		}
		// get book info
		var bookName string
		var exprice float64
		var price float64
		err = db.QueryRow("select name, exprice, price from books where book_id = ?", bookId).Scan(&bookName, &exprice, &price)
		if err != nil {
			log.Println(err)
			http.Error(context.Writer, "Unknown error", http.StatusNotFound)
			return
		}

		result = append(result, Order{OrderId: strconv.Itoa(orderId), CustomerId: strconv.Itoa(customerId),
			CustomerName: customerName, BookId: strconv.Itoa(bookId), OrderStatus: orderStatus, StartDate: startDate, EndDate: endDate,
			BookName: bookName, ExPrice: exprice, Price: price})
	}
	result_marshal, err := json.Marshal(result)
	fmt.Println(string(result_marshal))
	if err != nil {
		log.Fatal(err)
		http.Error(context.Writer, "json error", http.StatusUnauthorized)
		return
	}
	context.Writer.Write(result_marshal)
}

func InProcessOrder(context *gin.Context) {
	context.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	// do auth
	authToken := context.Request.Header.Get("Authorization")
	userEmail, err := MakeAuth(authToken)
	if err != nil {
		http.Error(context.Writer, err.Error(), http.StatusUnauthorized)
		return
	}
	// get user id
	var userId int
	err = db.QueryRow("select user_id from app_users where mail_address = ?",
		userEmail).Scan(&userId)

	rows, err := db.Query("select order_id, customer_id, book_id, order_status, start_date from orders where seller_id = ? and (order_status = 0 or order_status = 1)", userId)
	if err != nil {
		log.Println(err)
		http.Error(context.Writer, "Sql Error, try again", http.StatusNotFound)
		return
	}

	var result []Order

	for rows.Next() {
		var orderId int
		var customerId int
		var customerName string
		var bookId int
		var orderStatus int
		var startDate string
		if err := rows.Scan(&orderId, &customerId, &bookId, &orderStatus, &startDate); err != nil {
			log.Println(err)
			http.Error(context.Writer, "Unknown error", http.StatusNotFound)
			return
		}
		// get customer name
		err = db.QueryRow("select user_name from app_users where user_id = ?",
			customerId).Scan(&customerName)
		if err != nil {
			log.Println(err)
			http.Error(context.Writer, "Unknown error", http.StatusNotFound)
			return
		}
		// get book info
		var bookName string
		var exprice float64
		var price float64
		err = db.QueryRow("select name, exprice, price from books where book_id = ?", bookId).Scan(&bookName, &exprice, &price)
		if err != nil {
			log.Println(err)
			http.Error(context.Writer, "Unknown error", http.StatusNotFound)
			return
		}

		result = append(result, Order{OrderId: strconv.Itoa(orderId), CustomerId: strconv.Itoa(customerId),
			CustomerName: customerName, BookId: strconv.Itoa(bookId), OrderStatus: orderStatus, StartDate: startDate,
			BookName: bookName, ExPrice: exprice, Price: price})
	}
	result_marshal, err := json.Marshal(result)
	fmt.Println(string(result_marshal))
	if err != nil {
		log.Fatal(err)
		http.Error(context.Writer, "json error", http.StatusUnauthorized)
		return
	}
	context.Writer.Write(result_marshal)
}

func SendMessage(context *gin.Context) {
	context.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	body, err := ioutil.ReadAll(context.Request.Body)
	if err != nil {
		log.Println(err)
		http.Error(context.Writer, "Login failed!", http.StatusUnauthorized)
		return
	}

	var userData map[string]string
	json.Unmarshal(body, &userData)  // Touserid + content

	// first do authenticate
	authToken := context.Request.Header.Get("Authorization")
	userEmail, err := MakeAuth(authToken)
	if err != nil {
		http.Error(context.Writer, err.Error(), http.StatusUnauthorized)
		return
	}
	// get user id
	var userId int
	err = db.QueryRow("select user_id from app_users where mail_address = ?",
		userEmail).Scan(&userId)

	ToUserId, err := strconv.Atoi(userData["ToUserId"])
	if err != nil {   // not a integer
		http.Error(context.Writer, err.Error(), http.StatusNotFound)
		return
	}

	_, err = db.Exec("insert into message(from_id, to_id, date, content) value (?, ?, now(), ?)", userId, ToUserId, userData["Content"]);
	if err != nil {
		log.Println(err)
		http.Error(context.Writer, "Error at query", http.StatusNotFound)
		return
	}

	context.Writer.Write(body)
}

func GetRequest(context *gin.Context) {
	context.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	authToken := context.Request.Header.Get("Authorization")
	userEmail, err := MakeAuth(authToken)
	if err != nil {
		http.Error(context.Writer, err.Error(), http.StatusUnauthorized)
		return
	}
	fmt.Println(userEmail)

	rows, err := db.Query("select * from request")

	if err != nil {
		log.Println(err)
		http.Error(context.Writer, "Not a valid user", http.StatusNotFound)
		return
	}

	var result []Request


	for rows.Next() {
		var userId int
		var requestId int
		var title string
		var content string
		var date string

		// parse data
		if err := rows.Scan(&requestId, &userId, &title, &content, &date); err != nil {
			log.Fatal(err)
			http.Error(context.Writer, "Unknown error", http.StatusNotFound)
			return
		}

		var userName string
		// get Username from userid
		err := db.QueryRow("select user_name from app_users where user_id = ?", userId).Scan(&userName)
		if err != nil {
			http.Error(context.Writer, "Unknown error", http.StatusNotFound)
			return
		}


		// store the result
		result = append(result, Request{RequestId: requestId, UserId: strconv.Itoa(userId), UserName: userName, Title: title, Content: content, Date: date})
	}
	result_marshal, err := json.Marshal(result)
	fmt.Println(string(result_marshal))
	if err != nil {
		log.Fatal(err)
		http.Error(context.Writer, "json error", http.StatusUnauthorized)
		return
	}
	context.Writer.Write(result_marshal)
}

func GetMessage(context *gin.Context) {
	context.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	body, err := ioutil.ReadAll(context.Request.Body)
	if err != nil {
		log.Println(err)
		http.Error(context.Writer, "Login failed!", http.StatusUnauthorized)
		return
	}

	var userData map[string]string
	json.Unmarshal(body, &userData)

	// first do authenticate
	authToken := context.Request.Header.Get("Authorization")
	userEmail, err := MakeAuth(authToken)
	if err != nil {
		http.Error(context.Writer, err.Error(), http.StatusUnauthorized)
		return
	}
	// get user id
	var userId int
	err = db.QueryRow("select user_id from app_users where mail_address = ?",
		userEmail).Scan(&userId)

	ToUserId, err := strconv.Atoi(userData["ToUserId"])
	if err != nil {   // not a integer
		http.Error(context.Writer, err.Error(), http.StatusNotFound)
		return
	}

	// select data
	rows, err := db.Query("select * from message where from_id = ? and to_id = ? union select * from message " +
		"where to_id = ? and from_id = ? order by date desc", userId, ToUserId, userId, ToUserId)

	if err != nil {
		log.Fatal(err)
		http.Error(context.Writer, "Unknown error", http.StatusNotFound)
		return
	}

	var result []Message


	for rows.Next() {
		var message_id int
		var from_id int
		var to_id int
		var date string
		var content string
		if err := rows.Scan(&message_id, &from_id, &to_id, &date, &content); err != nil {
			log.Fatal(err)
			http.Error(context.Writer, "Unknown error", http.StatusNotFound)
			return
		}
		// store the result
		result = append(result, Message{MessageId: message_id, IfSelfSend: from_id == userId , Date: date, Content: content})
	}
	result_marshal, err := json.Marshal(result)
	fmt.Println(string(result_marshal))
	if err != nil {
		log.Fatal(err)
		http.Error(context.Writer, "json error", http.StatusUnauthorized)
		return
	}

	context.Writer.Write(result_marshal)


}

func GetPeople(context *gin.Context) {
	context.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	authToken := context.Request.Header.Get("Authorization")
	userEmail, err := MakeAuth(authToken)
	if err != nil {
		http.Error(context.Writer, err.Error(), http.StatusUnauthorized)
		return
	}
	fmt.Println(userEmail)

	// get the user info
	ToUserId, err := strconv.Atoi(context.Param("id"))
	if err != nil {
		http.Error(context.Writer, err.Error(), http.StatusUnauthorized)
		return
	}
	var ToUserName string
	var ToUserEmail string

	err = db.QueryRow("select user_name, mail_address from app_users where user_id = ?", ToUserId).Scan(&ToUserName, &ToUserEmail)
	if err != nil {
		log.Println(err)
		http.Error(context.Writer, "Not a valid user", http.StatusNotFound)
		return
	}

	result := People{Userid: ToUserId, UserName: ToUserName, UserEmail: ToUserEmail}
	result_marshal, err := json.Marshal(result)
	fmt.Println(string(result_marshal))
	if err != nil {
		log.Fatal(err)
		http.Error(context.Writer, "json error", http.StatusUnauthorized)
		return
	}

	context.Writer.Write(result_marshal)

}

func GetBook(context *gin.Context) {
	context.Writer.Header().Set("Access-Control-Allow-Origin", "*")

	authToken := context.Request.Header.Get("Authorization")
	userEmail, err := MakeAuth(authToken)
	if err != nil {
		http.Error(context.Writer, err.Error(), http.StatusUnauthorized)
		return
	}

	fmt.Println(userEmail)

	arg := context.Param("arg")
	if (arg == "all") {
		stm, err := db.Prepare("select book_id, posterID, name, exprice, price, ISBN, imageURL, date, description from books where status = 0")
		defer stm.Close()
		rows, err := stm.Query()
		if err != nil {
			log.Fatal(err)
			http.Error(context.Writer, "Unknown error", http.StatusUnauthorized)
			return
		}
		defer rows.Close()
		var result []Book
		for rows.Next() {
			var id int
			var posterID int
			var name string
			var exprice float64
			var price float64
			var ISBN string
			var imageURL string
			var date string
			var description string
			if err := rows.Scan(&id, &posterID, &name, &exprice, &price, &ISBN, &imageURL, &date, &description); err != nil {
				log.Fatal(err)
				http.Error(context.Writer, "Unknown error", http.StatusUnauthorized)
				return
			}
			// get the userinfo from PosterID
			var posterName string
			// verify the input
			err = db.QueryRow("select user_name from app_users where user_id = ?",
				posterID).Scan(&posterName)
			if err != nil {
				log.Println(err)
				http.Error(context.Writer, "login failed!", http.StatusUnauthorized)
				return
			}

			result = append(result, Book {BookId: strconv.Itoa(id), PosterId: posterID, PosterName: posterName, BookName: name, ExPrice: exprice, Price: price,
				ISBN: ISBN, ImageURL: imageURL, Date: date, Description: description})

		}
		result_marshal, err := json.Marshal(result)
		fmt.Println(string(result_marshal))
		if err != nil {
			log.Fatal(err)
			http.Error(context.Writer, "json error", http.StatusUnauthorized)
			return
		}

		context.Writer.Write(result_marshal)
	}

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
			"userid": userData["email"],
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
		userData["nickname"], userData["email"], sha_result, seed)
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
