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
	Query		map[string]interface{}				`json:"query"`
}

func (e ErrorResponse) Log() {
	// TODO : Print le JSON de log
	// Mettre en DB ?
	// utiliser logrus
	fmt.Println(e.Description,e.Query)

}

func (e ErrorResponse) Send() {
	respJSON, err := json.Marshal(e)
	if err != nil {
		http.Error(e.w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	http.Error(e.w, string(respJSON), e.Status)
}

type FileInfo struct {
	Id             int       `json:"-"`
	Path           string    `json:"-"`
	Url            string    `json:"url"`
	ExpirationDate time.Time `json:"expiration_date"`
	Filename       string    `json:"-"`
}

type API struct {
	fileDAO DAOFile
}

type DAOFile interface {
	Create(*FileInfo) error
	GetByUrl(*FileInfo) error
	Delete(*FileInfo) error
}

type FileDAO struct {
	db *pg.DB
}

func (fileDAO FileDAO) Create(file *FileInfo) error {
	return fileDAO.db.Insert(file)
}

func (fileDAO FileDAO) GetByUrl(file *FileInfo) error {
	return fileDAO.db.Model(file).Where("url = ?", file.Url).First()
}

func (fileDAO FileDAO) Delete(file *FileInfo) error {
	return fileDAO.db.Delete(file)
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

func handleError(w http.ResponseWriter, desc string, status int, err error, Query map[string]interface{}) {
	errResponse := ErrorResponse{
		Description: desc,
		Status:      status,
		err:         err,
		w:           w,
		Query:		Query,
	}
	errResponse.Log()
	errResponse.Send()
}

func (api API) encryptRoute(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {
		var timeNow time.Time
		var err error
		var expireDuration int
		var key []byte
		var cryptFileInfo FileInfo
		tmp := make(map[string]interface{})


		r.ParseMultipartForm(32 << 20)

		timeNow = time.Now().Local()

		// Get durée de vie de fichier : en nombre d'heures
		expireDuration, err = strconv.Atoi(r.FormValue("expiration"))
		if err != nil || (expireDuration != 1 && expireDuration != 24 && expireDuration != 168) {
			// la durée d'expiration n'a pas pu être transformée en Int
			tmp["query"] = strconv.Itoa(expireDuration)
			handleError(w, "La durée d'expiration est invalide. Veuillez rentrer 1,24,ou 168.", http.StatusBadRequest, err, tmp )
			return
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
			err = api.fileDAO.GetByUrl(&cryptFileInfo)
			if err == nil {
				// URL déjà prise
				// Logger le fait qu'une URL était déja prise (no break)
				tmp["query"] = "InvalidURL"
				handleError(w, "L'URL générée est déja prise.", http.StatusInternalServerError, err, tmp)
				return
				// 1 chance sur 20^61 de trouver la même combinaison
			} else {
				urlIsTaken = false
				cryptFileInfo.Url = tmpUrl
			}
		}
		if tries >= 10 {
			// After 10 attempts, no free url
			tmp["query"] = "InvalidURL10Retries"
			handleError(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError, err, tmp)
			return
		}

		nonce := bytes.Repeat([]byte{0}, 12)
		key = make([]byte, 32)
		if _, err = io.ReadFull(cryptoRand.Reader, key); err != nil {
			// Pas réussi à générer une clé aléatoire de 32 bits
			// Error 500
			tmp["query"]= "NoCreationOfKey"
			handleError(w, "Echec de la création de la clé aléatoire de 32 bits.", http.StatusInternalServerError, err, tmp )
			return
		}
		cipherAES, err := aes.NewCipher(key)
		if err != nil {
			// Fail to create cipher error 500
			tmp["query"]= "NoCreationOfCipher"
			handleError(w, "Echec de la création du cipher.", http.StatusInternalServerError, err, tmp)
			return

		}
		AESgcm, err := cipher.NewGCM(cipherAES)
		if err != nil {
			// Fail to create GCM error 500
			tmp["query"]= "NoCreationOfGCM"
			handleError(w, "Echec de la création du GCM.", http.StatusInternalServerError, err, tmp)
			return
		}

		// Récupérer le fichier
		//print("Recupération du fichier")
		uploadedFile, handler, err := r.FormFile("uploadfile")
		switch err {
		case nil:
			// do nothing
		case http.ErrMissingFile:
			// Failed to get a file
			// Error 400
			tmp["query"]="NofileFound"
			handleError(w, "Pas de fichier trouver à cette adresse.", http.StatusBadRequest, err, tmp)
			return
		default:
			// Failed to get a file
			// Error 400
			tmp["query"]="CantFindFile"
			handleError(w, "Echec lors de la récupération du fichier.", http.StatusBadRequest, err, tmp)
			return
		}

		defer uploadedFile.Close()

		uploadedFileBuffer := bytes.NewBuffer(nil)
		if _, err := io.Copy(uploadedFileBuffer, uploadedFile); err != nil {
			// Failed to upload the file
			tmp["query"]="FailedToUpload"
			handleError(w, "Echec lors de l'upload du fichier.", http.StatusInternalServerError, err, tmp)
			return
		}

		cryptFileBuffer := AESgcm.Seal(nil, nonce, uploadedFileBuffer.Bytes(), nil)

		cryptFileInfo.Path = "./uploads/" + cryptFileInfo.Url
		cryptFileInfo.Filename = handler.Filename

		// checker la bonne permission
		err = ioutil.WriteFile(cryptFileInfo.Path, cryptFileBuffer, 0644)
		if err != nil {
			// Failed to write crypted file to disk
			// Error 500
			tmp["query"]="FailedToWriteInDisk"
			handleError(w, "Echec lors de l'écriture du fichier crypté dans le disque.", http.StatusInternalServerError, err, tmp)
			return
		}
		// Ajout de ce fichier en DB
		err = api.fileDAO.Create(&cryptFileInfo)
		if err != nil {
			// Failed to insert fileInfo into DB
			// Error 500
			tmp["query"]="FailedToWriteInDB"
			handleError(w, "Echec lors de l'insertion des données dans la base de données.", http.StatusInternalServerError, err, tmp)
			return
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
			tmp["query"]="FailedToBuildJSONStruct"
			handleError(w, "Echec lors de la création du JSON (élément de réponse).", http.StatusInternalServerError, err,tmp )
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(encryptResponseJSON)
	}
}

func (api API) decryptRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {

		cryptFileInfo := new(FileInfo)
		tmp := make(map[string]interface{})
		var err error
		errResponse := ErrorResponse{
			w: w,
		}

		cryptFileInfo.Url = r.FormValue("url")
		if cryptFileInfo.Url == "" {

			// Répondre que l'url est vide
			tmp["query"]="URLEmpty"
			handleError(w, "L'URL est vide.", http.StatusBadRequest, err, tmp)
			return
		}

		// Récuperer URL dans DB + path du fichier + date de fin

		err = api.fileDAO.GetByUrl(cryptFileInfo)
		if err != nil {
			// URL cherchée pas dans DB
			tmp["query"]="URLNotInDB"
			handleError(w, "URL Invalide", http.StatusBadRequest, err, tmp)
			return
		}
		//si date de fin dépassée (maintenant supérieur à date fin)
		if cryptFileInfo.ExpirationDate.Before(time.Now().Local()) {
			//Erase du fichier dans db et serveur + ligne dans la DB
			err = os.Remove(cryptFileInfo.Path)
			if err != nil {
				errResponse.err = err
				errResponse.Log()
			}

			err = api.fileDAO.Delete(cryptFileInfo)
			if err != nil {
				errResponse.err = err
				errResponse.Log()
			}
			// répondre que la date est dépassée
			tmp["query"]="ExpiredDate"
			handleError(w, "La date d'expiration est dépassée.", http.StatusBadRequest, err, tmp)
			return
		}
		//Ask for key
		key := r.FormValue("key")
		if key == "" {
			// Répondre que la key est vide
			tmp["query"]="EmptyKey"
			handleError(w, "La clé est vide.", http.StatusBadRequest, err, tmp)
			return
		}
		//Vérifier les caractéristiques de la clé
		keyBytes, err := hex.DecodeString(key)
		if err != nil || len(keyBytes) != 32 {
			// Répondre que la clé n'est pas valide
			tmp["query"]="KeyLengthInvalid"
			handleError(w, "La clé est non valide.", http.StatusBadRequest, err, tmp)
			return
		}
		//Déchiffrer le fichier
		// create AES-GCM instance
		cipherAES, err := aes.NewCipher(keyBytes)
		if err != nil {
			tmp["query"]="NoCreationOfCipher"
			handleError(w, "La création du cipherAES à échoué.", http.StatusInternalServerError, err, tmp)
			return
		}
		AESgcm, err := cipher.NewGCM(cipherAES)
		if err != nil {
			tmp["query"]="NoCreationOfGCM"
			handleError(w, "La création du GCM à échoué.", http.StatusInternalServerError, err, tmp)
			return
		}
		// open input file
		cryptedFileBytes, err := ioutil.ReadFile(cryptFileInfo.Path)
		if err != nil {
			// Répondre qu'il y a eu une erreur interne lors de l'ouverture du fichier
			tmp["query"]="CantOpenFile"
			handleError(w, "Erreur interne lors de l'ouverture du fichier.", http.StatusInternalServerError, err, tmp)
			return
		}
		// Dechiffrement
		nonce := bytes.Repeat([]byte{0}, 12)
		decryptedFileBytes, err := AESgcm.Open(nil, nonce, cryptedFileBytes, nil)
		if err != nil {
			// Répondre que la clé n'est pas valable
			tmp["query"]="InvalidKey"
			handleError(w, "Dechiffrement impossible. La clé n'est pas valable.", http.StatusBadRequest, err, tmp)
			return
		}
		//Envoyer le fichier
		w.Header().Set("Content-Disposition", `attachment; filename="`+cryptFileInfo.Filename+`"`)
		//w.Header().Set("Content-Length", strconv.Itoa(len(decryptedFileBytes)/1024))
		// TODO: Trouver taille fichier (stocker la taille du fichier en db lors de l'upload)

		//Envoie du fichier au client
		if _, err = w.Write(decryptedFileBytes); err != nil {
			// Upload a crash
			tmp["query"]="CantSendFile"
			handleError(w, "L'upload du fichier a rencontré une erreur.", http.StatusInternalServerError, err, tmp)
			return
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
	db := new(pg.DB)
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
	defer db.Close()

	// Create Schema in db
	for retries := 0; retries < 3; retries++ {
		err = createSchema(db)
		if err != nil {
			time.Sleep(10 * time.Second)
		} else {
			break
		}
	}
	if err != nil {
		fmt.Println("Failed to connect to DB after 3 retries.")
		panic(err)
	}

	fileDAO := FileDAO{db:db}
	api := API{fileDAO:fileDAO}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("./static/")))
	mux.HandleFunc("/encrypt", api.encryptRoute)
	mux.HandleFunc("/decrypt", api.decryptRoute)

	handler := cors.Default().Handler(mux)
	http.ListenAndServe(":9090", handler)
}
