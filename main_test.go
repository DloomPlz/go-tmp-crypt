package main

import (
"net/http/httptest"
"testing"
"io/ioutil"
"fmt"
"errors"
	"os"
	"bytes"
	"mime/multipart"
	"path/filepath"
	"io"
	"net/http"
	"encoding/json"
	"time"

)

var Files []*FileInfo

type TestFileDAO struct {}

func (fileDAO TestFileDAO) Create(file *FileInfo) error {
	Files = append(Files,file)
	return nil
}

func (fileDAO TestFileDAO) GetByUrl(f *FileInfo) error {
	for _,file := range Files {
		if file.Url == f.Url {
			f.ExpirationDate = file.ExpirationDate
			f.Url = file.Url
			f.Filename = file.Filename
			f.Path = file.Path
			return nil
		}
	}
	return errors.New("File not found in DB")
}

func (fileDAO TestFileDAO) Delete(f *FileInfo) error {
	for i,file := range Files {
		if file.Id == f.Id {
			Files = append(Files[:i], Files[i+1:]...)
			return nil
		}
	}
	return nil
}


func TestEncryptRoute(t *testing.T) {

	fileDAO := TestFileDAO{}
	api := API{fileDAO:fileDAO}
	handler := api.encryptRoute

	//form values
	file, _ := os.Open("./test/halo.png")
	defer file.Close()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	uploadFile, _ := writer.CreateFormFile("uploadfile", filepath.Base(file.Name()))
	io.Copy(uploadFile, file)

	expiration, _ :=writer.CreateFormField("expiration")
	expiration.Write([]byte("1"))

	writer.Close()

	// body resp

	req, err := http.NewRequest("POST", "/encrypt", body)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handler(w, req)

	resp := w.Result()
	buff, _ := ioutil.ReadAll(resp.Body)

	//fmt.Println(resp.Header.Get("Content-Type"))
	if resp.StatusCode != 200 {
		t.Errorf("Erreur durant le test de chiffrement de l'image, got: %d, want: %d.", resp.StatusCode, 200)
	}

	// Get variables url and key
	var encryptResp EncryptResponse
	err = json.Unmarshal(buff,&encryptResp)
	if err!=nil{
		fmt.Println("error", err)
	}
	// Now Download Test

	handler = api.decryptRoute
	body = new(bytes.Buffer)
	writer = nil
	writer = multipart.NewWriter(body)

	url, _ :=writer.CreateFormField("url")
	url.Write([]byte(encryptResp.Url))


	key, _ :=writer.CreateFormField("key")
	key.Write([]byte(encryptResp.Key))


	writer.Close()

	// body resp

	req, err = http.NewRequest("POST", "/decrypt", body)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	handler(w, req)

	resp = w.Result()
	buff, _ = ioutil.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Errorf("Erreur durant le test de déchiffrement de l'image, got: %d, want: %d.", resp.StatusCode, 200)
	}
	//fmt.Println(resp.Header.Get("Content-Type"))
	//fmt.Println(string(buff))

	// -------------------- TEST ENCRYPT -------------

	// Test with wrong expiration date ( != 1 , 24 , 128)
	handler = api.encryptRoute

	//form values
	file, _ = os.Open("./test/halo.png")
	defer file.Close()
	body = &bytes.Buffer{}
	writer = multipart.NewWriter(body)
	uploadFile, _ = writer.CreateFormFile("uploadfile", filepath.Base(file.Name()))
	io.Copy(uploadFile, file)

	expiration, _ =writer.CreateFormField("expiration")
	expiration.Write([]byte("20")) // MAUVAISE DATE
	writer.Close()

	// body resp

	req, err = http.NewRequest("POST", "/encrypt", body)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	handler(w, req)

	resp = w.Result()
	buff, _ = ioutil.ReadAll(resp.Body)

	response := new(ErrorResponse)
	err = json.Unmarshal(buff,&response)
	if err != nil {
		t.Fatal("pas reussi a unmarshal la reponse")
	}
	if response.Query["query"] != "20" {
		t.Errorf("Erreur durant le test de chiffrement de l'image avec une date invalide, got: %d, want: %d.", response.Query["query"], 20)
	}
	//fmt.Println(resp.Header.Get("Content-Type"))


	// Test with no upload file

	handler = api.encryptRoute

	//form values
	body = &bytes.Buffer{}
	writer = multipart.NewWriter(body)


	expiration, _ =writer.CreateFormField("expiration")
	expiration.Write([]byte("1"))
	writer.Close()

	// body resp

	req, err = http.NewRequest("POST", "/encrypt", body)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	handler(w, req)

	resp = w.Result()
	buff, _ = ioutil.ReadAll(resp.Body)

	response = new(ErrorResponse)
	err = json.Unmarshal(buff,&response)
	if err != nil {
		t.Fatal("pas reussi a unmarshal la reponse")
	}
	if response.Query["query"] != "NofileFound" {
		t.Errorf("Erreur durant le test de chiffrement d'un fichier inexistant, got: %d, want: %d.", response.Query["query"], "NofileFound")
	}

	// ---------------------- TEST DECRYPT -------------
	// Blank url

	handler = api.decryptRoute
	body = new(bytes.Buffer)
	writer = nil
	writer = multipart.NewWriter(body)

	url, _ =writer.CreateFormField("url")
	url.Write([]byte(""))


	key, _ =writer.CreateFormField("key")
	key.Write([]byte(encryptResp.Key))


	writer.Close()

	// body resp

	req, err = http.NewRequest("POST", "/decrypt", body)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	handler(w, req)

	resp = w.Result()
	buff, _ = ioutil.ReadAll(resp.Body)

	response = new(ErrorResponse)
	err = json.Unmarshal(buff,&response)
	if err != nil {
		t.Fatal("pas reussi a unmarshal la reponse")
	}
	if response.Query["query"] != "URLEmpty" {
		t.Errorf("Erreur durant le test de déchiffrement d'un fichier avec une URL vide, got: %d, want: %d.", response.Query["query"], "URLEmpty")
	}

	// False URL

	handler = api.decryptRoute
	body = new(bytes.Buffer)
	writer = nil
	writer = multipart.NewWriter(body)

	url, _ =writer.CreateFormField("url")
	url.Write([]byte("DX18E8Rwcp5nYWM9kz7H"))


	key, _ =writer.CreateFormField("key")
	key.Write([]byte(encryptResp.Key))


	writer.Close()

	// body resp

	req, err = http.NewRequest("POST", "/decrypt", body)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	handler(w, req)

	resp = w.Result()
	buff, _ = ioutil.ReadAll(resp.Body)

	response = new(ErrorResponse)
	err = json.Unmarshal(buff,&response)
	if err != nil {
		t.Fatal("pas reussi a unmarshal la reponse")
	}
	if response.Query["query"] != "URLNotInDB" {
		t.Errorf("Erreur durant le test de déchiffrement d'un fichier avec une URL invalide, got: %d, want: %d.", response.Query["query"], "URLNotInDB")
	}

	// Date expired


	cryptFileInfo := new(FileInfo)
	cryptFileInfo.Url = "urlTest"
	now := time.Now()
	cryptFileInfo.ExpirationDate = now.AddDate(0, -1, 0) // -1 mois
	print(cryptFileInfo.ExpirationDate.String())
	fileDAO.Create(cryptFileInfo)


	handler = api.decryptRoute

	body = new(bytes.Buffer)
	writer = nil
	writer = multipart.NewWriter(body)

	url, _ =writer.CreateFormField("url")
	url.Write([]byte("urlTest"))


	key, _ =writer.CreateFormField("key")
	key.Write([]byte(""))
	writer.Close()


	// body resp

	req, err = http.NewRequest("POST", "/decrypt", body)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	handler(w, req)

	resp = w.Result()
	buff, _ = ioutil.ReadAll(resp.Body)

	response = new(ErrorResponse)
	err = json.Unmarshal(buff,&response)
	if err != nil {
		t.Fatal("pas reussi a unmarshal la reponse")
	}
	if response.Query["query"] != "ExpiredDate" {
		t.Errorf("Erreur durant le test de déchiffrement d'un fichier et la date limite est dépassé, got: %d, want: %d.", response.Query["query"], "ExpiredDate")
	}

	// Create another fake object in DB to use it for decrypt

	handler = api.encryptRoute

	//form values
	file, _ = os.Open("./test/halo.png")
	defer file.Close()
	body = &bytes.Buffer{}
	writer = multipart.NewWriter(body)
	uploadFile, _ = writer.CreateFormFile("uploadfile", filepath.Base(file.Name()))
	io.Copy(uploadFile, file)

	expiration, _ =writer.CreateFormField("expiration")
	expiration.Write([]byte("1"))

	writer.Close()

	// body resp

	req, err = http.NewRequest("POST", "/encrypt", body)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	handler(w, req)

	resp = w.Result()
	buff, _ = ioutil.ReadAll(resp.Body)

	//fmt.Println(resp.Header.Get("Content-Type"))
	if resp.StatusCode != 200 {
		t.Errorf("Erreur durant le test de chiffrement de l'image, got: %d, want: %d.", resp.StatusCode, 200)
	}

	// Get variables url and key
	var encryptResp2 EncryptResponse
	err = json.Unmarshal(buff,&encryptResp2)
	if err!=nil{
		fmt.Println("error", err)
	}

	// Blank key

	cryptFileInfo = new(FileInfo)
	cryptFileInfo.Url = "urlTest"
	now = time.Now()
	cryptFileInfo.ExpirationDate = now.AddDate(0, 1, 0) // -1 mois
	print(cryptFileInfo.ExpirationDate.String())
	fileDAO.Create(cryptFileInfo)


	handler = api.decryptRoute

	body = new(bytes.Buffer)
	writer = nil
	writer = multipart.NewWriter(body)

	url, _ =writer.CreateFormField("url")
	url.Write([]byte(encryptResp2.Url))


	key, _ =writer.CreateFormField("key")
	key.Write([]byte(""))
	writer.Close()


	// body resp

	req, err = http.NewRequest("POST", "/decrypt", body)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	handler(w, req)

	resp = w.Result()
	buff, _ = ioutil.ReadAll(resp.Body)

	response = new(ErrorResponse)
	err = json.Unmarshal(buff,&response)
	if err != nil {
		t.Fatal("pas reussi a unmarshal la reponse")
	}
	if response.Query["query"] != "EmptyKey" {
		t.Errorf("Erreur durant le test de déchiffrement d'un fichier et la clé secrete est vide, got: %d, want: %d.", response.Query["query"], "EmptyKey")
	}

	// Key length != 32

	handler = api.decryptRoute
	body = new(bytes.Buffer)
	writer = nil
	writer = multipart.NewWriter(body)

	url, _ =writer.CreateFormField("url")
	url.Write([]byte(encryptResp2.Url))


	key, _ =writer.CreateFormField("key")
	key.Write([]byte(encryptResp.Key[:len(encryptResp2.Key)-1]))


	writer.Close()

	// body resp

	req, err = http.NewRequest("POST", "/decrypt", body)
	req.Header.Add("Content-Type", writer.FormDataContentType())
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	handler(w, req)

	resp = w.Result()
	buff, _ = ioutil.ReadAll(resp.Body)

	response = new(ErrorResponse)
	err = json.Unmarshal(buff,&response)
	if err != nil {
		t.Fatal("pas reussi a unmarshal la reponse")
	}
	if response.Query["query"] != "KeyLengthInvalid" {
		t.Errorf("Erreur durant le test de déchiffrement d'un fichier et la clé secrete n'est pas composé de 32 caractères, got: %d, want: %d.", response.Query["query"], "KeyLengthInvalid")
	}


}


