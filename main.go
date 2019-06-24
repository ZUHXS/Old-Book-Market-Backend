// create table app_users( user_id int auto_increment, user_name varchar(40) not null, mail_address varchar(100) not null unique, password_hash varbinary(100), salt varbinary(20) not null, primary key(user_id));
// create table books( book_id int auto_increment primary key, posterID int, foreign key(posterID) references app_users(user_id), name varchar(50) not null, exprice double not null, price double not null, ISBN varchar(20) not null, imageURL varchar(400) not null, date DATE not null, description varchar(500) not null);
// insert into books(posterID, name, exprice, price, ISBN, imageURL, date, description) values(1, '数学分析上', 44.60, 24.00, "9787040295672", "https://img.alicdn.com/imgextra/i2/391838199/O1CN01FjStMt2ARBr7nzqZK_!!0-item_pic.jpg_430x430q90.jpg", now(), "真心求出，上面还有我的笔记，我的数分最后97分");
//insert into books(posterID, name, exprice, price, ISBN, imageURL, date, description) values(3, '计算机组成与设计：硬件/软件接口', 139.00, 56.80, "9787111608943", "https://img.alicdn.com/imgextra/i4/2130152348/O1CN011TDQQN43LtwrFKn_!!2130152348-2-item_pic.png_430x430q90.jpg", now(), "七成新，上面有三代学长的笔记以及Patt的亲笔签名");
//insert into books(posterID, name, exprice, price, ISBN, imageURL, date, description) values(3, 'PHP7内核剖析', 89.00, 30.00, "9787121328107", "https://img.alicdn.com/imgextra/i2/2695809921/O1CN01E7wNQp2N9rtuhuZFZ_!!0-item_pic.jpg_430x430q90.jpg", now(), "超棒的PHP入门教程");
//insert into books(posterID, name, exprice, price, ISBN, imageURL, date, description) values(5, 'PHP7内核剖析', 17.50, 7.00, "9787020135639", "https://img.alicdn.com/imgextra/i1/859515618/TB2X4pNih9YBuNjy0FfXXXIsVXa_!!859515618.jpg_430x430q90.jpg", now(), "史铁生先生充满哲思又极为人性化的代表作之一");
//insert into books(posterID, name, exprice, price, ISBN, imageURL, date, description) values(5, '鸟哥的Linux私房菜', 86.80, 40.50, "9787115472588", "https://img.alicdn.com/imgextra/i4/1049653664/TB2U2AwaNTpK1RjSZFGXXcHqFXa_!!1049653664-0-item_pic.jpg_430x430q90.jpg", now(), "超经典的Linux入门书");
// create table message( message_id int auto_increment primary key, from_id int, foreign key(from_id) references app_users(user_id), to_id int, foreign key(to_id) references app_users(user_id), date DATETIME not null, content varchar(1000) not null);
// insert into message(from_id, to_id, date, content) value (1, 3, now(), '请问我上次购买的数学分析下发货了吗？');
// insert into message(from_id, to_id, date, content) value (3, 1, now(), '发了');
// insert into message(from_id, to_id, date, content) value (3, 1, now(), '我帮你查查快递单号');
// insert into message(from_id, to_id, date, content) value (3, 1, now(), '寄的是顺丰，单号是xxx');
// insert into message(from_id, to_id, date, content) value (3, 1, now(), '你查询一下？');
// insert into message(from_id, to_id, date, content) value (1, 3, now(), 'okk我看到了，谢谢啊');
// create table request( request_id int auto_increment primary key, user_id int, foreign key(user_id) references app_users(user_id), title varchar(100) not null, content varchar(1000) not null, date DATE not null);
// insert into request(user_id, title, content, date) value (3, "求购数学分析", "多少钱都行，急求", now());
// insert into request(user_id, title, content, date) value (3, "想要一本普通物理学", "考试需要", now());
// insert into request(user_id, title, content, date) value (3, "有没有好书推荐？", "希望是文学史上的经典名著，可以私聊", now());
// insert into request(user_id, title, content, date) value (3, "想入门PHP，有推荐的入门书吗？", "非CS专业，希望可以讲的浅显易懂", now());
// insert into request(user_id, title, content, date) value (5, "有没有入门信息安全的图书？", "比如道哥的白帽子讲信息安全那种书", now());

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
	Book_id string
	Posterid int
	PosterName string
	Book_Name string
	Exprice float64
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
		stm, err := db.Prepare("select book_id, posterID, name, exprice, price, ISBN, imageURL, date, description from books")
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

			result = append(result, Book {Book_id: strconv.Itoa(id), Posterid: posterID, PosterName: posterName, Book_Name: name, Exprice: exprice, Price: price,
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