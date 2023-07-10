package main

import (
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	syslog "github.com/RackSec/srslog"
	"github.com/xoebus/ceflog"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/mpkondrashin/certalert/pkg/certs"
	"github.com/mpkondrashin/certalert/pkg/secureftp"
	"github.com/mpkondrashin/certalert/pkg/sms"
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
	flagTempDir       = "temp"
	flagThresholdDays = "days"
	flagIgnoreExpired = "ignore_expired"
	flagOnDays        = "on_days"

	flagSMSAddress         = "sms.address"
	flagSMSAPIKey          = "sms.api_key"
	flagSMSIgnoreTLSErrors = "sms.ignore_tls_errors"

	flagSFTPUsernameLength = "sftp.username_length"
	flagSFTPPasswordLength = "sftp.password_length"

	flagSyslogProto     = "syslog.proto"
	flagSyslogHost      = "syslog.host"
	flagSyslogPort      = "syslog.port"
	flagSyslogTag       = "syslog.tag"
	flagSyslogVendor    = "syslog.vendor"
	flagSyslogProduct   = "syslog.product"
	flagSyslogVersion   = "syslog.version"
	flagSyslogSignature = "syslog.signature"
	flagSyslogName      = "syslog.name"
	flagSyslogSeverity  = "syslog.severity"
	flagSyslogFacility  = "syslog.facility"

	flagSMTPFrom     = "smtp.from"
	flagSMTPTo       = "smtp.to"
	flagSMTPPassword = "smtp.password"
	flagSMTPHost     = "smtp.host"
	flagSMTPPort     = "smtp.port"
	flagSMTPSubject  = "smtp.subject"

	flagLogFileName  = "log.filename"
	flagLogAnonymize = "log.anonymize"
)

func Configure() {
	fs := pflag.NewFlagSet("", pflag.ExitOnError)

	fs.Int(flagThresholdDays, 0, "Alert on certificates to be expired within provided number of days")
	fs.String(flagOnDays, "", "Alert on certificates expiring on that precise date from today")
	fs.String(flagTempDir, "", "Folder for temporary files")
	fs.Bool(flagIgnoreExpired, false, "Alert only on about to expire certificates, ignoring already expired")

	fs.String(flagSMSAddress, "", "Tipping Point SMS address")
	fs.String(flagSMSAPIKey, "", "Tipping Point SMS API Key")
	fs.Bool(flagSMSIgnoreTLSErrors, false, "Ignore SMS TLS errors")

	fs.Int(flagSFTPUsernameLength, DefaultUsernameLength, "sFTP username length")
	fs.Int(flagSFTPPasswordLength, DefaultPasswordLength, "sFTP password length")

	fs.String(flagSyslogProto, "udp", "Syslog protocol (udp/tcp)")
	fs.String(flagSyslogHost, "", "Syslog host")
	fs.Int(flagSyslogPort, 514, "Syslog port")
	fs.String(flagSyslogTag, "certalert", "Syslog tag")
	fs.String(flagSyslogVendor, "Trend Micro", "CEF Vendor field value")
	fs.String(flagSyslogProduct, "Tipping Point SMS", "CEF Product field value")
	fs.String(flagSyslogVersion, "0", "CEF Version field value")
	fs.String(flagSyslogSignature, "cert", "CEF Signature ID field value")
	fs.String(flagSyslogName, "Certificate Update Required", "CEF Name field value")
	fs.Int(flagSyslogSeverity, 4, "CEF and Syslog Severity field value (0 - Emergency, 7 - Debug. Defatlt 4 - Warning)")
	fs.Int(flagSyslogFacility, 0, "Sys local facility number (0 - Local0, 7 - Local7")

	fs.String(flagSMTPFrom, "", "SMTP from email")
	fs.String(flagSMTPTo, "", "SMTP email to send alerts")
	fs.Int(flagSMTPPort, 25, "SMTP port")
	fs.String(flagSMTPHost, "", "SMTP server address")
	fs.String(flagSMTPSubject, "", "alert mail subject prefix")

	fs.String(flagLogFileName, "", "Filename for log file")
	fs.Bool(flagLogAnonymize, false, "Anonymize log file content")

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
	proto := viper.GetString(flagSyslogProto)
	switch proto {
	case "tcp", "udp":
	default:
		log.Fatalf("%s: syslog protocol is not udp or tcp", proto)
	}
	if viper.GetInt(flagThresholdDays) != 0 && viper.GetString(flagOnDays) != "" {
		log.Fatalf("Only one from %s and %s can be set", flagOnDays, flagThresholdDays)
	}
	if viper.GetInt(flagThresholdDays) == 0 && viper.GetString(flagOnDays) == "" {
		log.Fatalf("%s or %s should be set", flagOnDays, flagThresholdDays)
	}
	_, err = OnDay()
	if err != nil {
		log.Fatalf("%s: %v", flagOnDays, err)
	}
}

func ConfigureLogging() {
	logFileName := viper.GetString(flagLogFileName)
	if logFileName == "" {
		return
	}
	logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
	if err != nil {
		log.Fatal(err)
	}
	mw := io.MultiWriter(os.Stderr, logFile)
	log.SetOutput(mw)
}

func hide(v any) string {
	s := fmt.Sprintf("%v", v)
	hasher := sha1.New()
	hasher.Write([]byte(s))
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

func Hide(v any) string {
	if !viper.GetBool(flagLogAnonymize) {
		return fmt.Sprintf("%v", v)
	}
	return hide(v)
}

func OnDay() (result []uint64, err error) {
	onDays := viper.GetString(flagOnDays)
	if onDays == "" {
		return nil, nil
	}
	onDaysList := strings.Split(onDays, ",")
	for _, each := range onDaysList {
		v, err := strconv.ParseUint(each, 10, 64)
		if err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	return
}

func GetSMS() *sms.SMS {
	auth := sms.NewAPIKeyAuthorization(viper.GetString(flagSMSAPIKey))
	smsClient := sms.New("https://"+viper.GetString(flagSMSAddress), auth)
	return smsClient.SetInsecureSkipVerify(viper.GetBool(flagSMSIgnoreTLSErrors))
}

func GetLocalAddress() string {
	smsAddress := viper.GetString(flagSMSAddress)
	log.Printf("Dial SMS (%s)", Hide(smsAddress))
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
	path, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	currentDrive := path[:2]
	if !strings.HasPrefix(backupPath, currentDrive) {
		log.Fatalf("TEMP is on %s drive and not on current drive: %s", backupPath[:2], currentDrive)
	}
	backupPath = backupPath[2:]
	return strings.ReplaceAll(backupPath, "\\", "/")
}

func RunBackup(smsClient *sms.SMS, username, password, localIP, backupPath string) {
	backupPath = FilterBackupPath(backupPath)
	//log.Printf("RunBackup(%v, %s, %s, %s, %s)", smsClient, username, password, localIP, backupPath)
	location := fmt.Sprintf("%s:%s", localIP, backupPath)
	password = url.QueryEscape(password)
	options := sms.NewBackupDatabaseOptionsSFTP(location, username, password)
	options.SetSSLPrivateKeys(true).SetTimestamp(false)
	log.Printf("Initiate backup: %v -> %s", smsClient, Hide(localIP))
	err := smsClient.BackupDatabase(options)
	if err != nil {
		log.Fatalf("Backup database: %v", err)
	}
}

func IterateExpiredCertificate(backupName string, alertRequired AlertRequiredFunc, callback func(cert *x509.Certificate) error) error {
	log.Print("Process backup")
	return certs.Iterate(backupName, func(cert *x509.Certificate) error {
		if alertRequired(cert) {
			return callback(cert)
		}
		return nil
	})
}

func GetFacility(facility int) syslog.Priority {
	if facility < 0 {
		facility = 0
	}
	if facility > 7 {
		facility = 7
	}
	return [...]syslog.Priority{
		syslog.LOG_LOCAL0,
		syslog.LOG_LOCAL1,
		syslog.LOG_LOCAL2,
		syslog.LOG_LOCAL3,
		syslog.LOG_LOCAL4,
		syslog.LOG_LOCAL5,
		syslog.LOG_LOCAL6,
		syslog.LOG_LOCAL7,
	}[facility]
}

func GetSyslog() (*syslog.Writer, error) {
	host := viper.GetString(flagSyslogHost)
	if host == "" {
		return nil, nil
	}
	port := viper.GetInt(flagSyslogPort)
	proto := viper.GetString(flagSyslogProto)
	address := fmt.Sprintf("%s:%d", host, port)
	tag := viper.GetString(flagSyslogTag)
	priority := syslog.Priority(viper.GetInt(flagSyslogSeverity))
	priority |= GetFacility(viper.GetInt(flagSyslogFacility))
	return syslog.Dial(proto, address, priority, tag)
}

func GetCEFLogger() (*ceflog.Logger, error) {
	logWriter, err := GetSyslog()
	if logWriter == nil {
		return nil, err
	}
	vendor := viper.GetString(flagSyslogVendor)
	product := viper.GetString(flagSyslogProduct)
	version := viper.GetString(flagSyslogVersion)
	logger := ceflog.New(logWriter, vendor, product, version)
	return logger, nil
}

type AlertRequiredFunc func(cert *x509.Certificate) bool

func GetAlertRequiredFunc() AlertRequiredFunc {
	if viper.GetInt(flagThresholdDays) != 0 {
		return GetDaysAlertRequiredFunc()
	}
	if viper.GetString(flagOnDays) != "" {
		return GetOnDayAlertRequiredFunc()
	}
	log.Fatalf("Both %s and %s are set", flagThresholdDays, flagOnDays)
	return nil
}

func GetDaysAlertRequiredFunc() AlertRequiredFunc {
	thresholdDays := viper.GetInt(flagThresholdDays)
	interval := time.Duration(thresholdDays) * time.Hour * 24
	now := time.Now().Round(time.Hour * 24)
	threshold := now.Add(interval)
	ignoreExpired := viper.GetBool(flagIgnoreExpired)
	return func(cert *x509.Certificate) bool {
		aboutToExpire := cert.NotAfter.Before(threshold)
		expired := cert.NotAfter.Before(now)
		log.Printf("To expire within %d days: %v; expired: %v; SerialNumber: %v; Issuer: %s; Subject: %s; Expire date: %v",
			thresholdDays, aboutToExpire, expired, Hide(cert.SerialNumber), cert.Issuer, Hide(cert.Subject), cert.NotAfter)
		if expired && ignoreExpired {
			return false
		}
		return aboutToExpire
	}
}

func GetOnDayAlertRequiredFunc() AlertRequiredFunc {
	today := time.Now().Round(time.Hour * 24)
	type Interval struct {
		from time.Time
		to   time.Time
	}
	var intervals []Interval
	daysList, _ := OnDay()
	for _, days := range daysList {
		f := today.Add(time.Duration(days) * time.Hour * 24)
		t := today.Add(time.Duration(days+1) * time.Hour * 24)
		intervals = append(intervals, Interval{f, t})
	}
	return func(cert *x509.Certificate) bool {
		for _, interval := range intervals {
			beforeFrom := cert.NotAfter.Before(interval.from)
			afterTo := cert.NotAfter.After(interval.to)
			alert := !beforeFrom && !afterTo
			log.Printf("Today: %v; Expire before: %v (%v); Expire after: %v (%v); Send alert: %v; SerialNumber: %v; Issuer: %s; Subject: %s; Expire date: %v (Not before: %v)",
				today, beforeFrom, interval.from, afterTo, interval.to, alert, Hide(cert.SerialNumber), cert.Issuer, Hide(cert.Subject),
				cert.NotAfter, cert.NotBefore)
			if alert {
				return alert
			}
		}
		return false
	}
}

func ProcessBackup(backupName string) {
	logger, err := GetCEFLogger()
	if err != nil {
		log.Fatal(err)
	}

	err = IterateExpiredCertificate(backupName, GetAlertRequiredFunc(), func(cert *x509.Certificate) error {
		if logger != nil {
			logger.LogEvent(
				viper.GetString(flagSyslogSignature),
				viper.GetString(flagSyslogName),
				ceflog.Sev(viper.GetInt(flagSyslogSeverity)),
				ceflog.Ext(
					"SMS", viper.GetString(flagSMSAddress),
					"SerialNumber", cert.SerialNumber.String(),
					"Issuer", cert.Issuer.String(),
					"Subject", cert.Subject.String(),
					"ExpireDate", cert.NotAfter.String()),
			)
			log.Print("Syslog sent successfully!")
		} else {
			log.Printf("Syslog: %s is empty - skip sending syslog", flagSyslogHost)
		}
		if err := SendMail(cert); err != nil {
			log.Printf("SendMail: %v", err)
		} else {
			log.Print("Email sent successfully!")
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
}

func SendMail(cert *x509.Certificate) error {
	host := viper.GetString(flagSMTPHost)
	if host == "" {
		return fmt.Errorf("%s is empty - skip sending email", flagSMTPHost)
	}
	port := viper.GetInt(flagSMTPPort)

	password := viper.GetString(flagSMTPPassword)

	from := viper.GetString(flagSMTPFrom)
	to := strings.Split(viper.GetString(flagSMTPTo), ",")

	sms := viper.GetString(flagSMSAddress)
	subject := fmt.Sprintf("CertAlert from %s", sms)
	prefix := viper.GetString(flagSMTPSubject)
	if prefix != "" {
		subject = fmt.Sprintf("%s: %s", prefix, subject)
	}
	left := time.Until(cert.NotAfter) / (time.Hour * 24)
	text := fmt.Sprintf("Subject: %s\r\n\r\nSMS: %s\r\nFollowing certificate is about to be expired:\r\n\r\nSerialNumber: %v\r\nIssuer: %s\r\nSubject: %s\r\nExpire date: %v\r\nDays left: %d\r\n\r\n-- CertAlert",
		subject, sms, cert.SerialNumber, cert.Issuer, cert.Subject, cert.NotAfter, left)

	message := []byte(text)
	var auth smtp.Auth
	if password != "" {
		auth = smtp.PlainAuth("", from, password, host)
	}
	address := fmt.Sprintf("%s:%d", host, port)
	return smtp.SendMail(address, auth, from, to, message)
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

func GetTempDir() string {
	tempDir := viper.GetString(flagTempDir)
	if tempDir == "" {
		var err error
		tempDir, err = ioutil.TempDir(viper.GetString(flagTempDir), "ca-*")
		if err != nil {
			log.Fatalf("TempDir: %v", err)
		}
	}
	log.Printf("Temp folder: %s", tempDir)
	return tempDir
}

func LogSize(backupPath string) {
	info, err := os.Stat(backupPath)
	if err != nil {
		log.Fatalf("Stat: %v", err)
	}
	log.Printf("Got backup file: %s", formatFileSize(info.Size()))
}

func main() {
	Configure()
	ConfigureLogging()
	if len(os.Args) == 2 {
		_, err := os.Stat(os.Args[1])
		if err == nil {
			ProcessBackup(os.Args[1])
			return
		}
	}
	localIP := GetLocalAddress()
	log.Printf("Run local sFTP server")
	port := 22
	username := RandStringBytesRmndr(viper.GetInt(flagSFTPUsernameLength))
	password := RandStringBytesRmndr(viper.GetInt(flagSFTPPasswordLength))
	go secureftp.Run(username, password, localIP, port)
	smsClient := GetSMS()
	backupName := GetBackupFileName()
	tempDir := GetTempDir()
	backupPath := filepath.Join(tempDir, backupName)
	defer func(backupName string) {
		log.Print("Remove temporary folder")
		_ = os.RemoveAll(tempDir)
	}(backupName)
	RunBackup(smsClient, username, password, localIP, backupPath)
	LogSize(backupPath)
	ProcessBackup(backupPath)
}
