package middlewares

import (
	"net/http"
	helper "github.com/RaihanAnthony/helper_TB_Berkah_Jaya"
	config "github.com/RaihanAnthony/config-TB_Berkah_Jaya"
	"log"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// mengambil cookie dari http request
		c, err := r.Cookie("token")
		if err != nil {
			log.Println("Missing token cookie:", err)
			response := map[string]interface{}{"message": "Unauthorized"}
			helper.Response(w, response, http.StatusUnauthorized)
			return
		}

		// mengambil token value
		tokenString := c.Value
		claims := &config.JWTClaim{}
		//parsing token jwt
		token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error){
			return config.JWT_KEY, nil
		})
		if err != nil {
			switch err {
			case jwt.ErrTokenSignatureInvalid:
				// token invalid
				log.Println("Invalid token signature:", err)
				response := map[string]interface{}{"message": "Unauthorized"}
				helper.Response(w, response, http.StatusUnauthorized)
				return
			case jwt.ErrTokenExpired :
				// token expire
				log.Println("Token have expired:", err)
				response := map[string]interface{}{"message": "Unauthorized, Token Expired"}
				helper.Response(w, response, http.StatusUnauthorized)
				return
			default:
				log.Println("Error parsing token:", err)
				response := map[string]interface{}{"message": "Unauthorized"}
				helper.Response(w, response, http.StatusUnauthorized)
				return
			}
		}

		if !token.Valid {
			log.Println("Error token tidak valid")
			response := map[string]string{"message": "Unauthorized"}
			helper.Response(w, response, http.StatusUnauthorized)
			return
		}

		// inialisasi session untuk mengambil role dari user
		session, err := config.Store.Get(r, "berkah-jaya-session")
		if err != nil {
			log.Println("Error getting session:", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// memeriksa role dalam session
		role, ok := session.Values["role"]
		if !ok || role == nil {
			log.Println("Role is missing in session")
			response := map[string]string{"message": "Unauthorized"}
			helper.Response(w, response, http.StatusUnauthorized)
		}

		roleStr, ok := role.(string)
        if !ok {
            log.Println("Role is not a string:", role)
            response := map[string]string{"message": "Unauthorized"}
            helper.Response(w, response, http.StatusUnauthorized)
            return
        }
		
		// memeriksa endpoint
		if err := EndPointCanAccess(roleStr, r.URL.Path); err != nil {
			log.Println("Acces denied to endpoint:", r.URL.Path)
			http.Error(w, "endpoin tidak dapat di akses", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func EndPointCanAccess(role, endpoints string) error {
	var endpointAdmin = []string{
		"/berkahjaya/adminside/barang",
		"/berkahjaya/adminside/barang/inputbarang",
		"/berkahjaya/adminside/barang/updatebarang",
		"/berkahjaya/adminside/barang/deletebarang",
		"/berkahjaya/adminside/hadiah",
		"/berkahjaya/adminside/hadiah/inputhadiah",
		"/berkahjaya/adminside/hadiah/updatehadiah",
		"/berkahjaya/adminside/hadiah/deletehadiah",
		"/berkahjaya/adminside/pengajuan/poin",
		"/berkahjaya/adminside/pengajuan/poin/sendmsgggiftsarrive",
		"/berkahjaya/adminside/pengajuan/poin/finished",
		"/berkahjaya/adminside/pengajuan/poin/verify",
		"/berkahjaya/change/password",
		"/berkahjaya/users/data",
		"/berkahjaya/adminside/pengajuan/poin/verify/cancel",
		"/berkahjaya/adminside/pengajuan/hadiah",
	}

	var endpointCustomers = []string{
		"/berkahjaya/scan/poin",
		"/berkahjaya/tukar/poin/hadiah",
		"/berkahjaya/users/data",
		"/berkahjaya/change/password",
		"/berkahjaya/proses/poin/verify",
		"/berkahjaya/user/proses/hadiah",
		"/berkahjaya/gifts/have/change/user",
		"/berkahjaya/user/remove/nota/not/valid",
	}

	if role == "Admin" {
		for _, en := range endpointAdmin {
			if en == endpoints { 
				return nil
			}
		}
	} 

	if role == "Customers" { 
		for _, en := range endpointCustomers {
			if en == endpoints {
				return nil
			}
		}
	}

	return fmt.Errorf("access denied to endpoint: %s", endpoints)
}