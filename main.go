package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	cryptoRand "crypto/rand"
	"encoding/hex"
	"encoding/json"

	"fmt"
	"github.com/go-pg/pg"
	"github.com/rs/cors"
	"io"
	"io/ioutil"

	"github.com/go-pg/pg/orm"
	mathRand "math/rand"
	"net/http"
	"os"
	"strconv"
	"time"
)

var db *pg.DB

type FileInfo struct {
	Id             int       `json:"-"`
	Path           string    `json:"-"`
	Url            string    `json:"url"`
	ExpirationDate time.Time `json:"expiration_date"`
	Filename       string    `json:"-"`
}

type EncryptResponse struct {
	Url            string    `json:"url"`
	ExpirationDate time.Time `json:"expiration_date"`
	Filename       string    `json:"filename"`
	Key            string    `json:"key"`
}

type ErrorResponse struct {
	err         error               `json:"-"`
	w           http.ResponseWriter `json:"-"`
	Status      int                 `json:"status"`
	Description string              `json:"description"`
}

func (e ErrorResponse) Log() {
	// TODO : Print le JSON de log
	// Mettre en DB ?
	// utiliser logrus
	fmt.Println(e.err)

}

func (e ErrorResponse) Send() {
	respJSON, err := json.Marshal(e)
	if err != nil {
		http.Error(e.w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	http.Error(e.w, string(respJSON), e.Status)
}

func encryptRoute(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {

		var timeNow time.Time
		var err error
		var expireDuration int
		var key []byte
		var cryptFileInfo FileInfo
		errResponse := ErrorResponse{
			w: w,
		}

		r.ParseMultipartForm(32 << 20)

		timeNow = time.Now().Local()

		// Get durée de vie de fichier : en nombre d'heures
		expireDuration, err = strconv.Atoi(r.FormValue("expiration"))
		if err != nil || (expireDuration != 1 && expireDuration != 24 && expireDuration != 168) {
			// la durée d'expiration n'a pas pu être transformée en Int
			errResponse.Description = "La durée d'expiration est invalide. Veuillez rentrer 1,24,ou 168."
			errResponse.Status = http.StatusBadRequest
			errResponse.err = err
			errResponse.Log()
			errResponse.Send()
		}

		// date de fin = durée de vie + date maintenant
		cryptFileInfo.ExpirationDate = timeNow.Add(time.Hour * time.Duration(expireDuration))

		// Retry until url is free or 10 attempts
		tries := 0
		urlIsTaken := true
		var tmpUrl string
		for urlIsTaken && tries < 10 {
			tries++
			// Générer url
			tmpUrl = RandomString(20)
			// Vérification que l'URL est disponible
			err = db.Model(&FileInfo{}).Where("url = ?", cryptFileInfo.Url).First()
			if err == nil {
				// URL déjà prise
				// Logger le fait qu'une URL était déja prise (no break)
				errResponse.Description = "L'URL générée est déja prise."
				errResponse.err = err
				errResponse.Log()
				// 1 chance sur 20^61 de trouver la même combinaison
			} else {
				urlIsTaken = false
				cryptFileInfo.Url = tmpUrl
			}
		}
		if tries >= 10 {
			// After 10 attempts, no free url
			errResponse.Description = http.StatusText(http.StatusInternalServerError)
			errResponse.Status = http.StatusInternalServerError
			errResponse.Log()
			errResponse.Send()
		}

		nonce := bytes.Repeat([]byte{0}, 12)
		key = make([]byte, 32)
		if _, err = io.ReadFull(cryptoRand.Reader, key); err != nil {
			// Pas réussi à générer une clé aléatoire de 32 bits
			// Error 500
			errResponse.Description = "Echec de la création de la clé aléatoire de 32 bits."
			errResponse.Status = http.StatusInternalServerError
			errResponse.err = err
			errResponse.Log()
			errResponse.Send()
		}
		cipherAES, err := aes.NewCipher(key)
		if err != nil {
			// Fail to create cipher error 500
			errResponse.Description = "Echec de la création du cipher."
			errResponse.Status = http.StatusInternalServerError
			errResponse.err = err
			errResponse.Log()

		}
		AESgcm, err := cipher.NewGCM(cipherAES)
		if err != nil {
			// Fail to create GCM error 500
			errResponse.Description = "Echec de la création du GCM."
			errResponse.Status = http.StatusInternalServerError
			errResponse.err = err
			errResponse.Log()

		}

		// Récupérer le fichier
		uploadedFile, handler, err := r.FormFile("uploadfile")
		if err != nil {
			// Failed to get a file
			// Error 400
			errResponse.Description = "Echec lors de la récupération du fichier."
			errResponse.Status = http.StatusBadRequest
			errResponse.err = err
			errResponse.Log()
			errResponse.Send()
		}
		defer uploadedFile.Close()

		uploadedFileBuffer := bytes.NewBuffer(nil)
		if _, err := io.Copy(uploadedFileBuffer, uploadedFile); err != nil {
			// Failed to upload the file
			errResponse.Description = "Echec lors de l'upload du fichier."
			errResponse.Status = http.StatusInternalServerError
			errResponse.err = err
			errResponse.Log()

		}

		cryptFileBuffer := AESgcm.Seal(nil, nonce, uploadedFileBuffer.Bytes(), nil)

		cryptFileInfo.Path = "./uploads/" + cryptFileInfo.Url
		cryptFileInfo.Filename = handler.Filename

		// checker la bonne permission
		err = ioutil.WriteFile(cryptFileInfo.Path, cryptFileBuffer, 0644)
		if err != nil {
			// Failed to write crypted file to disk
			// Error 500
			errResponse.Description = "Echec lors de l'écriture du fichier crypté dans le disque."
			errResponse.Status = http.StatusInternalServerError
			errResponse.err = err
			errResponse.Log()

		}
		// Ajout de ce fichier en DB
		err = db.Insert(&cryptFileInfo)
		if err != nil {
			// Failed to insert fileInfo into DB
			// Error 500
			errResponse.Description = "Echec lors de l'insertion des données dans la base de données."
			errResponse.Status = http.StatusInternalServerError
			errResponse.err = err
			errResponse.Log()

		}

		// renvoyer URL + Date expiration + clé
		encryptResponse := EncryptResponse{
			Url:            cryptFileInfo.Url,
			ExpirationDate: cryptFileInfo.ExpirationDate,
			Filename:       cryptFileInfo.Filename,
			Key:            fmt.Sprintf("%032x", key),
		}
		encryptResponseJSON, err := json.Marshal(encryptResponse)
		if err != nil {
			// Failed to create JSON Struct
			// Error 500
			errResponse.Description = "Echec lors de la création du JSON (élément de réponse)."
			errResponse.Status = http.StatusInternalServerError
			errResponse.err = err
			errResponse.Log()

		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(encryptResponseJSON)
	}
}

func RandomString(strlen int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ0123456789"
	result := make([]byte, strlen)
	r := mathRand.New(mathRand.NewSource(time.Now().UnixNano()))
	for i := range result {
		result[i] = chars[r.Intn(len(chars))]
	}
	return string(result)
}

func decryptRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {

		var cryptFileInfo FileInfo
		var err error
		errResponse := ErrorResponse{
			w: w,
		}

		url := r.FormValue("url")
		if url == "" {

			// Répondre que l'url est vide
			errResponse.Description = "L'URL est vide."
			errResponse.Status = http.StatusBadRequest
			errResponse.err = err
			errResponse.Log()
			errResponse.Send()
		}

		//Récuperer URL dans DB + path du fichier + date de fin
		err = db.Model(&cryptFileInfo).Where("url = ?", url).First()
		if err != nil {
			// URL cherchée pas dans DB
			errResponse.Description = "URL Invalide."

			errResponse.err = err
			errResponse.Log()

			// Répondre que l'url est invalide
		}
		//si date de fin dépassée (maintenant supérieur à date fin)
		if cryptFileInfo.ExpirationDate.Before(time.Now().Local()) {
			//Erase du fichier dans db et serveur + ligne dans la DB
			err = os.Remove(cryptFileInfo.Path)
			if err != nil {
				errResponse.err = err
				errResponse.Log()
			}

			err = db.Delete(&cryptFileInfo)
			if err != nil {
				errResponse.err = err
				errResponse.Log()
			}
			// répondre que la date est dépassée
			errResponse.Description = "La date d'expiration est dépassée."
			errResponse.err = err
			errResponse.Log()
			errResponse.Send()
		}
		//Ask for key
		key := r.FormValue("key")
		if key == "" {

			// Répondre que la key est vide
			errResponse.Description = "La clé est vide."
			errResponse.Status = http.StatusBadRequest
			errResponse.err = err
			errResponse.Log()
			errResponse.Send()
		}
		//Vérifier les caractéristiques de la clé
		keyBytes, err := hex.DecodeString(key)
		if err != nil || len(keyBytes) != 32 {
			// Répondre que la clé n'est pas valide
			errResponse.Description = "La clé est non valide."
			errResponse.Status = http.StatusBadRequest
			errResponse.err = err
			errResponse.Log()
			errResponse.Send()
		}
		//Déchiffrer le fichier
		// create AES-GCM instance
		cipherAES, err := aes.NewCipher(keyBytes)
		if err != nil {
			errResponse.Description = "La création du cipherAES à échoué."
			errResponse.Status = http.StatusInternalServerError
			errResponse.err = err
			errResponse.Log()

		}
		AESgcm, err := cipher.NewGCM(cipherAES)
		if err != nil {
			errResponse.Description = "La création du GCM à échoué."
			errResponse.Status = http.StatusInternalServerError
			errResponse.err = err
			errResponse.Log()

			//Répondre qu'il y eu une erreur
		}
		// open input file
		cryptedFileBytes, err := ioutil.ReadFile(cryptFileInfo.Path)
		if err != nil {
			// Répondre qu'il y a eu une erreur interne lors de l'ouverture du fichier
			errResponse.Description = "Erreur interne lors de l'ouverture du fichier."
			errResponse.Status = http.StatusInternalServerError
			errResponse.err = err
			errResponse.Log()
		}
		// Dechiffrement
		nonce := bytes.Repeat([]byte{0}, 12)
		decryptedFileBytes, err := AESgcm.Open(nil, nonce, cryptedFileBytes, nil)
		if err != nil {
			errResponse.Description = "Dechiffrement impossible. La clé n'est pas valable."
			errResponse.Status = http.StatusBadRequest
			errResponse.err = err
			errResponse.Log()
			errResponse.Send()
			// Répondre que la clé n'est pas valable

		}

		//Envoyer le fichier
		w.Header().Set("Content-Disposition", `attachment; filename="`+cryptFileInfo.Filename+`"`)
		//w.Header().Set("Content-Length", strconv.Itoa(len(decryptedFileBytes)/1024))
		// TODO: Trouver taille fichier (stocker la taille du fichier en db lors de l'upload)

		//Envoie du fichier au client
		if _, err = w.Write(decryptedFileBytes); err != nil {
			// Upload a crash
			errResponse.Description = "L'upload du fichier a rencontré une erreur."
			errResponse.Status = http.StatusInternalServerError
			errResponse.err = err
			errResponse.Log()
		}

	}
}

func createSchema(db *pg.DB) error {
	for _, model := range []interface{}{&FileInfo{}} {
		err := db.CreateTable(model, &orm.CreateTableOptions{
			IfNotExists: true,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {

	// Lire variable d'environnement
	db_url := os.Getenv("DATABASE_URL")
	if db_url == "" {
		panic("variable db_url vide")
	}
	db_options, err := pg.ParseURL(db_url)
	if err != nil {
		panic(err)
	}
	db = pg.Connect(db_options)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Create Schema in db
	err = createSchema(db)
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/encrypt", encryptRoute)
	mux.HandleFunc("/decrypt", decryptRoute)
	handler := cors.Default().Handler(mux)
	http.ListenAndServe(":9090", handler)

}
