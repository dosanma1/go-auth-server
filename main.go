package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/jackc/pgx/v4"
	"golang.org/x/crypto/bcrypt"
)

var (
	nsCookieName         = "SID"
	nsRedirectCookieName = "SREDIRECT"
)

var ctx context.Context = context.Background()

func main() {
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerHandler)

	fmt.Printf("Starting server at port 5000\n")
	if err := http.ListenAndServe(":5000", nil); err != nil {
		log.Fatal(err)
	}

}

func authHandler(w http.ResponseWriter, r *http.Request) {
	hashKey, err := getKeys()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
	var s = securecookie.New(hashKey, nil)
	// get the cookie from the request
	if cookie, err := r.Cookie(nsCookieName); err == nil {
		value := make(map[string]string)
		// try to decode it
		if err = s.Decode(nsCookieName, cookie.Value, &value); err == nil {
			// if if succeeds set X-Forwarded-User header and return HTTP 200 status code
			w.Header().Add("X-WEBAUTH-USER", value["user"])
			w.Header().Add("X-WEBAUTH-NAME", value["name"])
			w.Header().Add("X-WEBAUTH-EMAIL", value["email"])
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	// otherwise return HTTP 401 status code
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		rd, ok := r.URL.Query()["rd"]
		if ok {
			http.SetCookie(w, &http.Cookie{
				Name:  nsRedirectCookieName,
				Value: rd[0],
				Path:  "/",
			})
		}
		renderTemplate(w, "login", false)
	} else if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			fmt.Fprintf(w, "ParseForm() err: %v", err)
			renderTemplate(w, "login", true)
			return
		}

		email := r.PostFormValue("email")
		password := r.PostFormValue("password")

		// nothing fancy here, it is just a demo so every user has the same password
		// and if it doesn't match render the login page and present user with error message
		if len(email) == 0 || len(password) == 0 {
			log.Println("No email/password found")
			renderTemplate(w, "login", true)
			return
		} else {
			var username, hash string

			conn, err := dbConnection()
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			defer conn.Close(ctx)

			row := conn.QueryRow(ctx, "SELECT username, hash FROM users WHERE email = $1;", email)
			if err := row.Scan(&username, &hash); err != nil {
				log.Println("No user found")
				renderTemplate(w, "login", true)
				return
			}

			if CheckPasswordHash(password, hash) {
				hashKey, err := getKeys()
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
				var s = securecookie.New(hashKey, nil)

				value := map[string]string{
					"user":  username,
					"email": email,
				}

				// encode username to secure cookie
				if encoded, err := s.Encode(nsCookieName, value); err == nil {
					cookie := &http.Cookie{
						Name:    nsCookieName,
						Value:   encoded,
						Expires: time.Now().AddDate(1, 0, 0),
						Path:    "/",
					}
					http.SetCookie(w, cookie)
				}

				// after successful login redirect to original destination (if it exists)
				var redirectUrl = "/"
				if cookie, err := r.Cookie(nsRedirectCookieName); err == nil {
					redirectUrl = cookie.Value

					// ... and delete the original destination holder cookie
					http.SetCookie(w, &http.Cookie{
						Name:    nsRedirectCookieName,
						Value:   "deleted",
						Expires: time.Now().Add(time.Hour * -24),
						Path:    "/",
					})
				}

				http.Redirect(w, r, redirectUrl, http.StatusFound)
			} else {
				log.Println("Email or password incorrect")
				renderTemplate(w, "login", true)
				return
			}

		}
	} else {
		log.Printf("Method %s not allowed", r.Method)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			fmt.Fprintf(w, "ParseForm() err: %v", err)
			renderTemplate(w, "login", true)
			return
		}

		username := r.PostFormValue("username")
		email := r.PostFormValue("email")
		password := r.PostFormValue("password")

		if len(username) == 0 || len(email) == 0 || len(password) == 0 {
			log.Println("All fields required")
			http.Error(w, fmt.Sprint("All fields required"), http.StatusBadRequest)
			return
		}

		hash, err := HashPassword(password)
		if err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		conn, err := dbConnection()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		defer conn.Close(ctx)

		tx, err := conn.Begin(ctx)
		if err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(ctx)

		var id uuid.UUID
		if err := tx.QueryRow(ctx,
			"INSERT INTO users (username, email, hash) VALUES ($1, $2, $3) RETURNING id", username, email, hash).Scan(&id); err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		err = tx.Commit(ctx)
		if err != nil {
			log.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(fmt.Sprintf("%s created successfully!", email)))
	} else {
		log.Printf("Method %s not allowed", r.Method)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func renderTemplate(w http.ResponseWriter, tmpl string, err bool) {
	t, _ := template.ParseFiles("./static/" + tmpl + ".html")
	t.Execute(w, err)
}

func getKeys() ([]byte, error) {
	signBytes, err := ioutil.ReadFile("./access-private.pem")
	if err != nil {
		log.Println("unable to read private key", "error", err)
		return nil, errors.New("could not generate access token. please try again later")
	}

	return signBytes, nil
}

func dbConnection() (*pgx.Conn, error) {
	config, err := pgx.ParseConfig(
		fmt.Sprintf(
			"postgres://%s:%s@%s:%s/%s?sslmode=require",
			os.Getenv("COCKROACHDB_USER"),
			os.Getenv("COCKROACHDB_PASS"),
			os.Getenv("COCKROACHDB_HOST"),
			os.Getenv("COCKROACHDB_PORT"),
			os.Getenv("COCKROACHDB_DB")))
	if err != nil {
		return nil, fmt.Errorf("error configuring the database: %s", err)
	}

	db, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("error connecting to the database: %s", err)
	}

	return db, nil
}
