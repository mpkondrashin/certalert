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
	"path/filepath"
	"strings"
	"time"

	"github.com/mpkondrashin/certalert/pkg/certs"
	"github.com/mpkondrashin/certalert/pkg/rsa"
	"github.com/mpkondrashin/certalert/pkg/secureftp"
	"github.com/mpkondrashin/certalert/pkg/sms"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	DefaultUsernameLength = 16
	DefaultPasswordLength = 16
)

const (
	EnvPrefix = "CERTALERT"
)

const (
	ConfigFileName = "config"
	ConfigFileType = "yaml"
)

const (
	flagSMSAddress         = "sms.address"
	flagSMSAPIKey          = "sms.api_key"
	flagSMSIgnoreTLSErrors = "sms.ignore_tls_errors"
	flagUsernameLength     = "u_length"
	flagPasswordLength     = "p_length"
)

func Configure() {
	fs := pflag.NewFlagSet("", pflag.ExitOnError)
	fs.String(flagSMSAPIKey, "", "Tipping Point SMS API Key")
	fs.Bool(flagSMSIgnoreTLSErrors, false, "Ignore SMS TLS errors")
	fs.Int(flagUsernameLength, DefaultUsernameLength, "sFTP username length")
	fs.Int(flagPasswordLength, DefaultPasswordLength, "sFTP password length")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	if err := viper.BindPFlags(fs); err != nil {
		log.Fatal(err)
	}
	viper.SetEnvPrefix(EnvPrefix)
	viper.AutomaticEnv()

	viper.SetConfigName(ConfigFileName)
	viper.SetConfigType(ConfigFileType)
	path, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(path)
		viper.AddConfigPath(dir)
	}
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		_, ok := err.(viper.ConfigFileNotFoundError)
		if !ok {
			log.Fatal(err)
		}
	}
	if viper.GetString(flagSMSAddress) == "" {
		log.Fatalf("Missing %s", flagSMSAddress)
	}
	if viper.GetString(flagSMSAPIKey) == "" {
		log.Fatalf("Missing %s", flagSMSAPIKey)
	}
}

func GetSMS() *sms.SMS {
	auth := sms.NewAPIKeyAuthorization(viper.GetString(flagSMSAPIKey))
	smsClient := sms.New("https://"+viper.GetString(flagSMSAddress), auth)
	return smsClient.SetInsecureSkipVerify(viper.GetBool(flagSMSIgnoreTLSErrors))
}

func GetLocalAddress() string {
	smsAddress := viper.GetString(flagSMSAddress)
	log.Printf("Dial SMS (%s)", smsAddress)
	localIP, err := GetOutboundIP(smsAddress + ":443")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Local address %v", localIP)
	return localIP.String()
}

func GetBackupFileName() string {
	backupBaseName := strings.ToLower(RandStringBytesRmndr(16))
	return backupBaseName + ".zip"
}

func RunBackup(smsClient *sms.SMS, username, password, localIP, backupName string) {
	log.Printf("RunBackup(%v, %s, %s, %s, %s)", smsClient, username, password, localIP, backupName)
	location := fmt.Sprintf("%s:/%s", localIP, backupName)
	//	location := fmt.Sprintf("%s:2022/%s", localIP, backupName)
	password = url.QueryEscape(password)
	options := sms.NewBackupDatabaseOptionsSFTP(location, username, password)
	options.SetSSLPrivateKeys(true).SetTimestamp(false)
	log.Print("Initiate backup")
	err := smsClient.BackupDatabase(options)
	if err != nil {
		log.Fatal(err)
	}
	info, err := os.Stat(backupName)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Got backup file: %d byes", info.Size())
}

func ProcessBackup(backupName string) {
	log.Print("Process backup")
	err := certs.Iterate(backupName, func(cert *x509.Certificate) error {
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

func RandStringBytesRmndr(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}

func main() {
	Configure()
	localIP := GetLocalAddress()
	log.Print("Generate private key")
	privateKey, err := rsa.Private()
	if err != nil {
		log.Fatal(err)
	}
	port := 22
	log.Printf("Run local sFTP server")
	username := RandStringBytesRmndr(viper.GetInt(flagUsernameLength))
	password := RandStringBytesRmndr(viper.GetInt(flagPasswordLength))
	log.Print("1Username: ", username)
	log.Print("1Password: ", password)
	go secureftp.Run(username, password, privateKey, localIP, port)
	smsClient := GetSMS()
	backupName := GetBackupFileName()
	defer func(backupName string) {
		log.Printf("Remove %s", backupName)
		_ = os.Remove(backupName)
	}(backupName)
	time.Sleep(5 * time.Second)
	log.Print("2Username: ", username)
	log.Print("2Password: ", password)
	RunBackup(smsClient, username, password, localIP, backupName)
	ProcessBackup(backupName)
}
