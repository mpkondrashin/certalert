// An example SFTP server implementation using the golang SSH package.
// Serves the whole filesystem visible to the user, and has a hard-coded username and password,
// so not for real use!
package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mpkondrashin/certalert/pkg/certs"
	"github.com/mpkondrashin/certalert/pkg/rsa"
	"github.com/mpkondrashin/certalert/pkg/secureftp"
	"github.com/mpkondrashin/certalert/pkg/sms"
)

const (
	UsernameLength = 16
	PasswordLength = 16
)

func main() {
	//	smsAddress := "10.34.32.6"
	smsAddress := "192.168.3.202"
	log.Printf("Dial SMS (%s)", smsAddress)
	localIP, err := GetOutboundIP(smsAddress + ":443")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Local address %v", localIP)
	user := RandStringBytesRmndr(UsernameLength)
	password := RandStringBytesRmndr(PasswordLength)
	log.Print("Generate private key")
	privateKey, err := rsa.Private()
	if err != nil {
		log.Fatal(err)
	}
	port := 2022
	//log.Printf("User: %s, password: %s, port: %d", user, password, port)
	log.Printf("Run local sFTP server")
	go secureftp.Run(user, password, privateKey, localIP.String(), port)
	apiKey := "A95BE8AB-AE00-45C5-B813-A9A2FDC27E5B"
	auth := sms.NewAPIKeyAuthorization(apiKey)
	smsClient := sms.New("https://"+smsAddress, auth).SetInsecureSkipVerify(true)
	backupBaseName := strings.ToLower(RandStringBytesRmndr(16))
	backupName := backupBaseName + ".zip"
	defer func() {
		if err := os.Remove(backupName); err != nil {
			log.Fatal(err)
		}
	}()
	location := fmt.Sprintf("%s:%d:/%s", localIP, port, backupName)
	password = url.QueryEscape(password)
	options := sms.NewBackupDatabaseOptionsSFTP(location, user, password)
	options.SetSSLPrivateKeys(true).SetTimestamp(false)
	log.Print("Initiate backup")
	err = smsClient.BackupDatabase(options)
	if err != nil {
		log.Fatal(err)
	}
	info, err := os.Stat(backupName)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Got backup file: %d byes", info.Size())
	log.Print("Process backup")
	//	backupZip := "sms_042420231012.bak"
	err = certs.Iterate(backupName, func(cert *x509.Certificate) error {
		log.Print("Version: ", cert.Version)
		log.Print("SerialNumber: ", cert.SerialNumber)
		log.Print("Issuer: ", cert.Issuer)
		log.Print("Subject: ", cert.Subject)
		log.Print("KeyUsage: ", cert.KeyUsage)
		log.Print("Not before: ", cert.NotBefore)
		log.Print("Not after: ", cert.NotAfter)
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
}

func GetOutboundIP(address string) (net.IP, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	return localAddr.IP, nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func RandStringBytesRmndr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}
