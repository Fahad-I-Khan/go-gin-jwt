// main.go
package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/cors"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	ID       uint   `json:"id" gorm:"primaryKey;autoIncrement"`
	Username string `json:"user" gorm:"unique;not null"`
	Password string `json:"email" gorm:"not null"`
}

var db *gorm.DB
var jwtKey = []byte("secret_key")

func initDatabase() {
	var err error
	dsn := "host=postgres user=postgres password=postgres dbname=jwt_example port=5432 sslmode=disable"
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to database")
	}
	db.AutoMigrate(&User{})
}

func register(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}

	user := User{Username: req.Username, Password: string(hashedPassword)}
	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

func login(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var user User
	if err := db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"exp":      time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// tokenString, err := token.SignedString(jwtKey)
	// if err != nil {
	// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
	// 	return
	// }

	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "/", "", false, true)
	fmt.Println("Setting cookie:", tokenString)

	c.JSON(http.StatusOK, gin.H{"message": "You are logged in"})
}

func authenticate(c *gin.Context) {
	// tokenString := c.GetHeader("Authorization")
	// if tokenString == "" {
	// 	c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
	// 	return
	// }

	tokenString, err := c.Cookie("Authorization")

	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token's signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token", "details": err.Error()})
		return
	}

	fmt.Println("Token received:", tokenString)

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		var user User
		if err := db.First(&user, claims["sub"]).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User Not Found"})	
		}

		if user.ID == 0 {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		c.Set("user", user)
	}
}

func main() {
	initDatabase()

	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}))
	
	r.POST("/register", register)
	r.POST("/login", login)
	r.GET("/protected", authenticate)

	r.OPTIONS("/*path", func(c *gin.Context) {
		c.AbortWithStatus(204)
	})

	r.Run(":8080")
	
}

/*
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzYxNTk2NjYsInVzZXJuYW1lIjoidGVzdHVzZXIifQ.CyQzy7MEBzjZvo9NxjGFJIuFiO62R8kWQBLtAwabt-Q"
}
	testuser 2
*/

/*
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzYxNzA3MjEsInVzZXJuYW1lIjoidGVzdHVzZXIgMyJ9.N7AlOODZy-P6vS1QeobCW0ZpXsUvz27Fkl16fH9AeFE"
}
	testuser 2
*/

/*

 */
