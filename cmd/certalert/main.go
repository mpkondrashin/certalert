// An example SFTP server implementation using the golang SSH package.
// Serves the whole filesystem visible to the user, and has a hard-coded username and password,
// so not for real use!
package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mpkondrashin/certalert/pkg/certs"
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
	flagTempDir            = "temp"
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
	log.Printf("SMS connection succeeded")
	log.Printf("Local address %v", localIP)
	return localIP.String()
}

func GetBackupFileName() string {
	backupBaseName := strings.ToLower(RandStringBytesRmndr(16))
	return backupBaseName + ".zip"
}

func FilterBackupPath(backupPath string) string {
	if runtime.GOOS != "windows" {
		return backupPath
	}
	if !strings.HasPrefix(backupPath, "C:") {
		log.Fatalf("TEMP is not on C: drive: %s", backupPath)
	}
	backupPath = backupPath[2:]
	return strings.ReplaceAll(backupPath, "\\", "/")
}

func RunBackup(smsClient *sms.SMS, username, password, localIP, backupPath string) {
	backupPath = FilterBackupPath(backupPath)
	log.Printf("RunBackup(%v, %s, %s, %s, %s)", smsClient, username, password, localIP, backupPath)
	location := fmt.Sprintf("%s:%s", localIP, backupPath)
	//	location := fmt.Sprintf("%s:2022/%s", localIP, backupName)
	password = url.QueryEscape(password)
	options := sms.NewBackupDatabaseOptionsSFTP(location, username, password)
	options.SetSSLPrivateKeys(true).SetTimestamp(false)
	log.Print("Initiate backup")
	err := smsClient.BackupDatabase(options)
	if err != nil {
		log.Fatalf("Backup database: %v", err)
	}
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
	/*
		privateKey, err := rsa.Private()
		if err != nil {
			log.Fatal(err)
		}
	*/
	port := 22
	log.Printf("Run local sFTP server")
	username := RandStringBytesRmndr(viper.GetInt(flagUsernameLength))
	password := RandStringBytesRmndr(viper.GetInt(flagPasswordLength))
	tempDir, err := ioutil.TempDir(viper.GetString(flagTempDir), "ca-*")
	if err != nil {
		log.Fatalf("TempDir: %v", err)
	}
	log.Printf("Temp folder: %s", tempDir)
	ready := make(chan struct{})
	go secureftp.Run(username, password, localIP, port, ready)
	smsClient := GetSMS()
	backupName := GetBackupFileName()
	backupPath := filepath.Join(tempDir, backupName)
	defer func(backupName string) {
		log.Print("Remove temporary folder")
		//_ = os.RemoveAll(tempDir)
	}(backupName)
	<-ready
	log.Print("sFTP is ready")
	RunBackup(smsClient, username, password, localIP, backupPath)
	info, err := os.Stat(backupPath)
	if err != nil {
		log.Fatalf("Stat: %v", err)
	}
	log.Printf("Got backup file: %d byes", info.Size())
	ProcessBackup(backupPath)
}
