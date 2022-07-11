package main

import (
	"context"
	"crypto/ecdsa"
	cryptoRand "crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	mathRand "math/rand"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

var sessions Sessions

type Session struct {
	Username   string
	Challenge  string
	SPKI       string
	IssuedAt   time.Time `json:"iat"`
	Expiration time.Time `json:"exp"`
}

type Sessions struct {
	sync.Mutex
	sessions map[string]Session
}

func generate(n uint, reader func(p []byte) (n int, err error)) (string, error) {
	b := make([]byte, n)
	_, err := reader(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func allow(username string, password string) bool {
	if username == "" || password == "" {
		return false
	}
	return true
}

func public(u *url.URL) bool {
	if u.Path == "/login" || u.Path == "/favicon.ico" {
		return true
	}
	p := path.Clean(u.Path)
	if strings.HasPrefix(p, "/css/") || strings.HasPrefix(p, "/js/") {
		return true
	}
	return false
}

func home(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeFile(w, req, "html/index.html")
}

func login(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet || req.Method == http.MethodHead ||
		req.Method == http.MethodOptions {
		http.ServeFile(w, req, "html/login.html")
		return
	}
	if req.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed),
			http.StatusMethodNotAllowed)
		return
	}

	req.Body = http.MaxBytesReader(w, req.Body, 1<<20)
	err := req.ParseMultipartForm(0)
	if err != nil && !errors.Is(err, http.ErrNotMultipart) {
		http.Error(w, http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}
	defer req.Body.Close()

	username := req.PostForm.Get("username")
	password := req.PostForm.Get("password")
	spki := req.PostForm.Get("spki")

	if !allow(username, password) || spki == "" {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
		return
	}

	t := token(w)
	c := challenge(w)
	sessions.Lock()
	sessions.sessions[t] = Session{
		Username:   username,
		Challenge:  c,
		SPKI:       spki,
		IssuedAt:   time.Now().UTC(),
		Expiration: time.Now().UTC().Add(5 * time.Minute),
	}
	sessions.Unlock()
	http.Redirect(w, req, "/", http.StatusSeeOther)
}

func logout(w http.ResponseWriter, req *http.Request) {
	clear(w, req)
	http.Redirect(w, req, "/login", http.StatusSeeOther)
}

func submit(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed),
			http.StatusMethodNotAllowed)
		return
	}

	req.Body = http.MaxBytesReader(w, req.Body, 1<<20)
	err := req.ParseMultipartForm(0)
	if err != nil && !errors.Is(err, http.ErrNotMultipart) {
		http.Error(w, http.StatusText(http.StatusBadRequest),
			http.StatusBadRequest)
		return
	}
	defer req.Body.Close()

	digest := req.PostForm.Get("sign")
	spki := req.Context().Value("spki").(string)
	challenge := req.Context().Value("challenge").(string)
	if !check(spki, challenge, digest) {
		http.Error(w, http.StatusText(http.StatusForbidden),
			http.StatusForbidden)
		return
	}
	http.ServeFile(w, req, "html/submit.html")
}

func auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if public(r.URL) {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie("token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		sessions.Lock()
		session, ok := sessions.sessions[cookie.Value]
		if !ok || time.Now().After(session.Expiration) ||
			time.Since(session.IssuedAt) > 1*time.Hour {
			sessions.Unlock()
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		delete(sessions.sessions, cookie.Value)
		t := token(w)
		sessions.sessions[t] = Session{
			Username:   session.Username,
			Challenge:  challenge(w),
			SPKI:       session.SPKI,
			IssuedAt:   session.IssuedAt,
			Expiration: time.Now().UTC().Add(5 * time.Minute),
		}
		sessions.Unlock()

		ctx := context.WithValue(r.Context(), "username", session.Username)
		ctx = context.WithValue(ctx, "spki", session.SPKI)
		ctx = context.WithValue(ctx, "challenge", session.Challenge)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// func csrf(next http.Handler) http.Handler {
// 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		if r.Method == http.MethodGet || r.Method == http.MethodHead ||
// 			r.Method == http.MethodOptions {
// 			next.ServeHTTP(w, r)
// 			return
// 		}
//
// 		next.ServeHTTP(w, r)
// 	})
// }

func security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; object-src 'none';")
		w.Header().Set("X-Frame-Options", "deny")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

func clean() {
	for range time.Tick(1 * time.Minute) {
		sessions.Lock()
		for token, session := range sessions.sessions {
			if time.Now().After(session.Expiration) ||
				time.Since(session.IssuedAt) > 1*time.Hour {
				delete(sessions.sessions, token)
			}
		}
		sessions.Unlock()
	}
}

func challenge(w http.ResponseWriter) string {
	c, err := generate(18, mathRand.Read)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "challenge",
		Value:    c,
		Path:     "/",
		MaxAge:   0,
		Secure:   true,
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
	})
	return c
}

func token(w http.ResponseWriter) string {
	t, err := generate(18, cryptoRand.Read)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    t,
		Path:     "/",
		MaxAge:   0,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return t
}

func clear(w http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("token")
	if err == nil {
		sessions.Lock()
		delete(sessions.sessions, cookie.Value)
		sessions.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "challenge",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
	})
}

func check(spki string, data string, digest string) bool {
	block, _ := pem.Decode([]byte("-----BEGIN PUBLIC KEY-----\n" +
		spki + "\n-----END PUBLIC KEY-----\n"))
	if block == nil {
		return false
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}

	pubKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false
	}

	hash := sha512.New384()
	hash.Write([]byte(data))

	if len(digest) != 128 {
		return false
	}
	rBytes, err := base64.StdEncoding.DecodeString(digest[:64])
	if err != nil {
		return false
	}
	sBytes, err := base64.StdEncoding.DecodeString(digest[64:])
	if err != nil {
		return false
	}

	r := big.NewInt(0).SetBytes(rBytes)
	s := big.NewInt(0).SetBytes(sBytes)

	return ecdsa.Verify(pubKey, hash.Sum(nil), r, s)
}

func init() {
	mathRand.Seed(time.Now().UnixNano())
	sessions.sessions = make(map[string]Session)
}

func main() {
	mux := http.NewServeMux()
	mux.Handle("/css/", http.FileServer(http.Dir("")))
	mux.Handle("/js/", http.FileServer(http.Dir("")))
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/logout", logout)
	mux.HandleFunc("/submit", submit)
	mux.HandleFunc("/", home)

	go clean()
	s := &http.Server{
		Addr:           ":8080",
		Handler:        security(auth(mux)),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.ListenAndServe())
}
