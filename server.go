package main

import (
	"database/sql"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var jwtKey = []byte("wakeuptoreality")

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}
type OTP struct {
	ID       int    `json:"id"`
	OTP      string `json:"otp"`
	Username string `json:"username"`
}
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func main() {
	var err error
	db, err = sql.Open("mysql", "aditya:AdityaPass123@tcp(localhost:3306)/testdb")

	if err != nil {
		log.Fatal(err)
	}

	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://127.0.0.1:5500"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	r.POST("/signup", signupHandler)
	r.POST("/login", loginHandler)
	r.POST("/request-otp", requestOTPHandler)
	r.POST("/verify-otp", verifyOTPHandler)
	r.GET("/protected", authMiddleware, protectedHandler)
	r.Run(":8080")
}
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func signupHandler(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Input"})
		return
	}

	if len(user.Username) < 3 || len(user.Username) > 20 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username must be 3-20 characters long"})
		return
	}

	if len(user.Password) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters long"})
		return
	}
	hashedPassword, err := HashPassword(user.Password)

	_, err = db.Exec("INSERT INTO user (username, password) VALUES (?, ?)", user.Username, hashedPassword)
	if err != nil {
		log.Println("Error inserting user:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving user data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User saved successfully"})
}

func loginHandler(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Input"})
		return
	}
	var StoredPassword string
	err := db.QueryRow("SELECT password FROM user WHERE Username=?", user.Username).Scan(&StoredPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid credentials"})
		return
	}
	if !CheckPasswordHash(user.Password, StoredPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Password"})
		return
	}
	expiration_time := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiration_time.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": tokenString})

}

func generateOTP() string {
	rand.Seed(time.Now().UnixNano())
	return strconv.Itoa(rand.Intn(10000))
}

func requestOTPHandler(c *gin.Context) {
	var user OTP
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Input"})
		return
	}
	otp := generateOTP()
	_, err := db.Exec("INSERT INTO otps(username,otp) VALUES(?,?)", user.Username, otp)
	if err != nil {
		log.Fatal(err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "OTP sent successfully"})
}

func verifyOTPHandler(c *gin.Context) {
	var user OTP
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Input"})
		return
	}

	var storedOTP string
	err := db.QueryRow("SELECT otp FROM otps WHERE username=?", user.Username).Scan(&storedOTP)
	if err != nil {
		log.Fatal(err)
		return
	}
	if storedOTP == user.OTP {
		_, err = db.Exec("DELETE FROM otps WHERE username=?", user.Username)
		if err != nil {
			log.Fatal(err)
			return
		} else {
			c.JSON(http.StatusOK, gin.H{"message": "OTP verified successfully"})
		}
	} else {
		c.JSON(http.StatusOK, gin.H{"message": "Invalid OTP"})
	}
}

func authMiddleware(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")

	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		c.Abort()
		return
	}
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		c.Abort()
		return
	}

	c.Set("username", claims.Username)
	c.Next()

}

func protectedHandler(c *gin.Context) {
	username, _ := c.Get("username")
	c.JSON(http.StatusOK, gin.H{"message": "Hello, " + username.(string)})
}
