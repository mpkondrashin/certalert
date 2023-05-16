
# CertAlert Update Your SSL Certificates On Time!

**CertAlert provide ability to receive alerts on all certificates in Tipping Point SMS that are about to expire**

## How to use:
1. Create API Key
2. Write config file
3. Download and run CertAlert

### API Key
1. Open Tipping Point SMS
2. Go to Admin -> Authentication and Authorization -> Users
3. Create New user and add it into auperuser group
4. Save API Key

### Write config file
Create following minimal configuration file
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
If email or syslog alert is not needed, just delete appropriate section.

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

## Options

CertAlert provides following ways to provide options:
1. Configuration file config.yaml. Application seeks for this file in its current folder or folder of CertAlert executable
2. Environment variables
3. Command line parameters

Full config file explained:
```yaml
days: 14 # This is the defaule value
temp: # Temporary folder to use for SMS backup file. If empty, it is assumed to be system temporary folder
sms:
  address: # IP address or dns name
  api_key: # SMS API Key
  ignore_tls_errors: false # Can be set to true if SMS has no correct certificate
smtp:
  host: # IP address or dns name
  port: 25
  from: # email of alert sender
  to: # email of alert recipient
  password: # SMTP auth password
syslog:
  host: # IP address or dns name
  proto: udp # or tcp. udp - default
  port: 514 # this is the default value
  severity: 4 # Warning
  facility: 0 # LOCAL0
```

To set these parameters through commandline, for example to ignore TLS errors:
```commandline
certalert --sms.ignore_tls_errors
```

To set these parameters through environment variable, example for API Key:
```commandline
CERTALERT_SMS.API_KEY=A95BE8AB-AE11-45C5-B813-A9A2FDC27E5B certalert
```

## BUGS

### On Windows - %TEMP% and certalert.exe on same drive!
On Windows, system TEMP folder should be on same drive and certalert.exe program (actually as current folder). If it is not so, "temp" parameter of configuration can be used, e.g. "temp: D:\TEMP" in config.yaml

### Bidirectional connectivity
Must be available bidirectional connectivity from host running CertAlert to SMS and back!