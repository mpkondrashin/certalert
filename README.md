
# CertAlert — Update TLS Certificates In Your Tipping Point SMS On Time!

**CertAlert alerts on certificates in Tipping Point SMS that are about to expire**

## How to use:
1. Create API Key
2. Write config file
3. Download and run CertAlert executable

### Create API Key
1. Open Tipping Point SMS
2. Go to Admin -> Authentication and Authorization -> Users
3. Create new user and add it to the superuser group
4. Save API Key

### Write config file
Create following minimal configuration file:
```yaml
days: 14
sms:
  address: 1.2.3.4
  api_key: A95BE8AB-AE11-45C5-B813-A9A2FDC27E5B
  ignore_tls_errors: true
smtp:
  host: 2.3.4.5
  from: alert@domain.com
  to: admin@domain.com
syslog:
  host: 4.5.6.7
```
If email or syslog alert is not needed, just omit appropriate section totally.

### Run CertAlert

Download certalert executable for your platfrom from  [releases](https://github.com/mpkondrashin/certalert/releases/latest)

Run following command (for Windows):
```commandline
certalert.exe
```
for Linux:
```commandline
./certalert
```

For production use, certalert should run regularly using operating system scheduled run possibility (Windows Task Scheduler/crontab). In this case two options are available:
1. Run certalert once a week (days: 7) or once in two weeks (days: 14) and alert on all certificates about to expire within this peroid of time. For this "days" options should be used.
1. Run certalert daily and alert of certificates to expire on particular day or days in the future. Option on_days should be used in this case.

## Options

CertAlert provides following ways to provide options:
1. Configuration file config.yaml. Application seeks for this file in its current folder or folder of CertAlert executable
2. Environment variables
3. Command line parameters

Full config file explained:
```yaml
days: 14 # This is the defaule value
ignore_expired: # Alert only on about to expire certificates, ignoring already expired. Default value: false
# on_days: 14,30 - comma separated list of days from today to alert on certificates expiering on these dates.
# This option can not be used togather with "days"
temp: # Temporary folder to use for SMS backup file. If empty, it is assumed to be system temporary folder
sms:
  address: # IP address or dns name
  api_key: # SMS API Key
  ignore_tls_errors: false # Can be set to true if SMS has no correct certificate
smtp:
  host: # IP address or dns name of MTA used to send alerts
  port: 25
  from: # email of alert sender
  to: # email of alert recipient
  password: # SMTP auth password
  subject: # Subject prefix
syslog:
  host: # IP address or dns name of Syslog server
  proto: udp # or tcp. udp - default
  port: 514 # this is the default value
  severity: 4 # Warning
  facility: 0 # LOCAL0
log:
  filename: # log file name.
  anonymize: false # default - false. Removes from log data that can be considered as confidential (IP addresses).
```

To set these parameters through commandline, use following notation: <section>.<parameter>. For example to ignore TLS errors use following command line option:
```commandline 
certalert --sms.ignore_tls_errors
```

To set these parameters through environment variable, add CERTALERT_ prefix and put "_" (underscore) between section and option. Example for API Key:
```commandline
CERTALERT_SMS_API_KEY=A95BE8AB-AE11-45C5-B813-A9A2FDC27E5B certalert
```

## Logging

CertAlert can write log to the file if filename is configured in configuration file or command line option "--log.filename".
Please note that log file is not rotated or limited by size anyhow.

### Anonymization

To remove frome the log file data, that can be considered as confidential, i.e. IP addresses, anonimyze option from log section should be set to true. It will autimatically obfuscate IP addresses and URLs.

Note: Within same certalert run, same values (IP addresses) will be obfuscated to the same strings, but restoring original values is not possible.

## Known Issues

### On Windows - %TEMP% and certalert.exe on same drive!
On Windows, system TEMP folder should be on same drive and certalert.exe program (actually as current folder). If it is not so, "temp" parameter of configuration can be used, e.g. "temp: D:\TEMP" in config.yaml or TMP environment variable can be set.

### Bidirectional connectivity
Bidirectional connectivity must be provided from host running CertAlert to SMS and back.

### IPv6
If using IPv6 address for SMS, please put it in square brackets.