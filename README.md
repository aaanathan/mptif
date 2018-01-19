# Multi Purpose Threat Intel Framework

##### A threat intel framework with malware analysis capability . User can check malware files against three different malware provider's engines . Included functionality to check IOC details of hashes , urls , IPs and domains from different resources.

### Resources available for Win Exe analysis.
#### •	AvCaesar 
#### •	Virus Scan Jotti 
#### •	Metadefender

### Resources availabe for Hash analysis.
#### •	Virus Total 
#### •	ShadowServer 
#### •	IBMxForceXchange

### Resources availabe for URL analysis.
#### •	Virus Total
#### •	Google SafeBrowse
#### •	UrlQuery.net

### Resources availabe for IP analysis
#### •	IBMxForce Xchange
#### •	Cymon.IO

### Resource availabe for Domain analysis
#### •	Cymon.IO

## Getting Started

##### git clone https://github.com/diljithishere/mptif.git
##### cd mptif/src
#### Open apiconfig.cfg under src\config folder and update with api keys from following vendors
#### GoogleSafeBrowse
#### VirusScan.Jotti
#### MetaDefender
#### Cymon.IO
#### IBMxForceXchange
#### Update AppPort if necessary (Optional)

##### go get github.com/PuerkitoBio/goquery
##### go build mptif.go (This command will generate mptif executable file)

#### Run exe 
##### mptif.exe

##### Use your browser to : http://localhost:8085

### Prerequisites

#### Go 1.9

## Built With
Go Lang

## Author

* **Diljith S** - *Initial work* - (https://github.com/diljithishere)

