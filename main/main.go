package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/Div9851/smartnote-backend/api"
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/elastic/go-elasticsearch/v7"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

//Jwks is JSON Web Key Set
type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

//JSONWebKeys is a JSON data structure that represents a cryptographic key
type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

/*
ENVIRONMENT VARIABLES

PORT
AUTH0_DOMAIN (http://example.com)
AUTH0_AUDIENCE
INDEX_NAME
*/

func main() {
	authDomain := os.Getenv("AUTH0_DOMAIN")
	authAudience := os.Getenv("AUTH0_AUDIENCE")
	port := os.Getenv("PORT")

	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			// Verify 'aud' claim
			aud := authAudience
			checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
			if !checkAud {
				return token, errors.New("invalid audience")
			}
			// Verify 'iss' claim
			iss := authDomain
			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
			if !checkIss {
				return token, errors.New("invalid issuer")
			}

			cert, err := getPemCert(token)
			if err != nil {
				panic(err.Error())
			}

			result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
			return result, nil
		}, SigningMethod: jwt.SigningMethodRS256,
	})

	r := mux.NewRouter()
	r.Handle("/notes/new_note",
		jwtMiddleware.Handler(http.HandlerFunc(PostNoteHandler))).Methods("POST", "OPTIONS")
	r.Handle("/notes/match_notes",
		jwtMiddleware.Handler(http.HandlerFunc(SearchNotesHandler))).Methods("GET", "OPTIONS")
	r.Handle("/notes/{noteID}",
		jwtMiddleware.Handler(http.HandlerFunc(HandlerMux))).Methods("GET", "POST", "DELETE", "OPTIONS")

	corsWrapper := cors.New(cors.Options{
		AllowedMethods: []string{"GET", "POST", "DELETE"},
		AllowedHeaders: []string{"Content-Type", "Origin", "Accept", "*"},
	})
	http.ListenAndServe(":"+port, corsWrapper.Handler(r))
}

func getToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	return strings.TrimPrefix(authHeader, "Bearer ")
}

func getUserID(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		cert, err := getPemCert(token)
		if err != nil {
			return nil, err
		}
		result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		return result, nil
	})
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !token.Valid || !ok {
		return "", fmt.Errorf("token is invalid")
	}
	return claims["sub"].(string), nil
}

func getPemCert(token *jwt.Token) (string, error) {
	authDomain := os.Getenv("AUTH0_DOMAIN")

	cert := ""
	resp, err := http.Get(authDomain + "/.well-known/jwks.json")

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("unable to find appropriate key")
		return cert, err
	}

	return cert, nil
}

//PostNoteHandler will be called
//when the user makes a POST request to /notes/new_note endpoint.
func PostNoteHandler(w http.ResponseWriter, r *http.Request) {
	indexName := os.Getenv("INDEX_NAME")
	bonsaiURL := os.Getenv("BONSAI_URL")
	token := getToken(r)
	userID, err := getUserID(token)
	if err != nil {
		http.Error(w, token+" "+err.Error(),
			http.StatusUnauthorized)
		return
	}
	es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{
			bonsaiURL,
		},
	})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	var reqBody map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	content, exist := reqBody["content"]
	if !exist {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	noteID, err := api.PostNote(es, indexName, userID, content.(string))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	resBody, err := json.Marshal(map[string]interface{}{
		"noteID": noteID,
	})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(resBody)
}

//HandlerMux will be called
//when the user makes a GET/POST/DELETE request to /notes/{noteID} endpoint.
func HandlerMux(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		FetchNoteHandler(w, r)
	case "POST":
		UpdateNoteHandler(w, r)
	case "DELETE":
		DeleteNoteHandler(w, r)
	}
}

//FetchNoteHandler will be called
//when the user makes a GET request to /notes/{noteID} endpoint.
func FetchNoteHandler(w http.ResponseWriter, r *http.Request) {
	indexName := os.Getenv("INDEX_NAME")
	bonsaiURL := os.Getenv("BONSAI_URL")
	token := getToken(r)
	userID, err := getUserID(token)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{
			bonsaiURL,
		},
	})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	vars := mux.Vars(r)
	note, err := api.FetchNoteByID(es, indexName, vars["noteID"])
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	author := note["userID"].(string)
	if author != userID {
		http.Error(w, http.StatusText(http.StatusForbidden),
			http.StatusForbidden)
		return
	}
	resBody, err := json.Marshal(note)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(resBody)
}

//UpdateNoteHandler will be called
//when the user makes a POST request to /notes/{noteID} endpoint.
func UpdateNoteHandler(w http.ResponseWriter, r *http.Request) {
	indexName := os.Getenv("INDEX_NAME")
	bonsaiURL := os.Getenv("BONSAI_URL")
	token := getToken(r)
	userID, err := getUserID(token)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{
			bonsaiURL,
		},
	})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	vars := mux.Vars(r)
	var reqBody map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	content, exist := reqBody["content"]
	if !exist {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if err := api.UpdateNote(es, indexName, userID, vars["noteID"], content.(string)); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully updated"))
}

//DeleteNoteHandler will be called
//when the user makes a DELETE request to /notes/{noteID} endpoint.
func DeleteNoteHandler(w http.ResponseWriter, r *http.Request) {
	indexName := os.Getenv("INDEX_NAME")
	bonsaiURL := os.Getenv("BONSAI_URL")
	token := getToken(r)
	userID, err := getUserID(token)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{
			bonsaiURL,
		},
	})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	vars := mux.Vars(r)
	if err := api.DeleteNote(es, indexName, userID, vars["noteID"]); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully deleted"))
}

//SearchNotesHandler will be called
//when the user makes a GET request to /notes/match_notes endpoint.
func SearchNotesHandler(w http.ResponseWriter, r *http.Request) {
	indexName := os.Getenv("INDEX_NAME")
	bonsaiURL := os.Getenv("BONSAI_URL")
	token := getToken(r)
	userID, err := getUserID(token)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized),
			http.StatusUnauthorized)
		return
	}
	es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{
			bonsaiURL,
		},
	})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	query := r.URL.Query()
	_, exist := query["searchText"]
	if !exist {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	searchText := query["searchText"][0]
	_, exist = query["from"]
	from, err := strconv.ParseFloat(query["from"][0], 64)
	if !exist || err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	_, exist = query["size"]
	size, err := strconv.ParseFloat(query["size"][0], 64)
	if !exist || err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	searchResult, err := api.SearchNotes(es, indexName, userID, searchText, int(from), int(size))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	resBody, err := json.Marshal(searchResult)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError),
			http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(resBody)
}
