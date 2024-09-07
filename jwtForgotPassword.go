package middlewares

import (
	"time"
	"log"
	"github.com/golang-jwt/jwt/v5"
	config "github.com/RaihanMalay21/config-tb-berkah-jaya"
)

// GenerateResetToken generates a JWT token for password reset
func GenerateResetToken(email string) (string, error) {

	expTime := time.Now().Add(5 * time.Minute)
	tokenBeforeSigned := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"exp": expTime.Unix(),
	})

	token, err := tokenBeforeSigned.SignedString(config.JWT_KEY)
	if err != nil {
		log.Println("Error cant signeture token function GenerateResetToken")
		return "", err
	}

	return token, nil
}

// VerifyResetToken verifies the JWT token
func VerifyResetToken(tokenStr string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return config.JWT_KEY, nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims["email"].(string), nil
	}
	return "", err
}