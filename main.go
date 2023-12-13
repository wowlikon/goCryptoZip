package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func createHash(key string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return hasher.Sum(nil)
}

func Base64ToFilename(b64 []byte) string {
	if len(b64) == 0 {
		return ""
	}

	encoded := base64.StdEncoding.EncodeToString(b64)
	// Replacing "/" with "-" to avoid errors in file creation
	filename := strings.Replace(encoded, "/", "-", -1)
	return filename
}

func FilenameToBase64(b64 string) ([]byte, error) {
	if b64 == "" {
		return make([]byte, 0), nil
	}

	filename := strings.Replace(b64, "-", "/", -1)
	// Replacing "-" with "/" to avoid errors in file creation
	decoded, err := base64.StdEncoding.DecodeString(filename)
	return decoded, err
}

func encrypt(plaintext []byte, passphrase string) ([]byte, error) {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	b := base64.StdEncoding.EncodeToString(plaintext)
	ciphertext := make([]byte, aes.BlockSize+len(b))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))

	return ciphertext, nil
}

func decrypt(ciphertext []byte, passphrase string) ([]byte, error) {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)

	return base64.StdEncoding.DecodeString(string(ciphertext))
}

func zipDir(src string, dst string, passphrase string) error {
	var err error
	var f *os.File

	if f, err = os.Create(dst); err != nil {
		return err
	}
	defer f.Close()

	w := zip.NewWriter(f)
	defer w.Close()

	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			relPath, err := encrypt([]byte(path[len(src):]), passphrase)
			if err != nil {
				return err
			}
			zipFile, err := w.Create(Base64ToFilename(relPath))
			if err != nil {
				return err
			}

			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			buf := new(bytes.Buffer)
			if _, err := io.Copy(buf, file); err != nil {
				return err
			}

			encryptedData, err := encrypt(buf.Bytes(), passphrase)
			if err != nil {
				return err
			}

			_, err = zipFile.Write(encryptedData)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func unzipDir(src, dst string, passphrase string) error {
	var err error
	var r *zip.ReadCloser

	os.MkdirAll(filepath.Dir(dst), 0755)

	r, err = zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		byteRelPath, err := FilenameToBase64(f.Name)
		if err != nil {
			return err
		}
		relPath, err := decrypt([]byte(byteRelPath), passphrase)
		if err != nil {
			return err
		}

		filePath := filepath.Join(dst, string(relPath))
		if f.FileInfo().IsDir() {
			os.MkdirAll(filePath, f.Mode())
		} else {
			os.MkdirAll(filepath.Dir(filePath), 0755)

			var fileReader io.ReadCloser
			fileReader, err = f.Open()
			if err != nil {
				return err
			}
			defer fileReader.Close()

			buf := new(bytes.Buffer)
			if _, err := io.Copy(buf, fileReader); err != nil {
				return err
			}

			decryptedData, err := decrypt(buf.Bytes(), passphrase)
			if err != nil {
				return err
			}

			err = os.WriteFile(filePath, decryptedData, f.Mode())
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func main() {
	operation := os.Args[1]
	src_file := os.Args[2]
	dst_file := os.Args[3]
	passphrase := os.Args[4]

	if operation == "unzip" {
		err := unzipDir(src_file, dst_file, passphrase)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("File unzipped successfully!")
		}
	} else if operation == "zip" {
		err := zipDir(src_file, dst_file, passphrase)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("Zip archive created successfully!")
		}
	}
}
