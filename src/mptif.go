package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"text/template"
	"time"

	"./avcaesar"
	"./cymonio"
	"./ibmxforce"
	"./jotti"
	"./metadefender"
	"./safebrowse"
	"./shadowserver"
	"./threatintelstructs"
	"./urlquerynet"
	"./virustotal"
)

var mmsatpl *template.Template
var apikeys threatintelstructs.APIs

type ScanResults struct {
	Vtscanres                map[string]string
	VtUploadedFileInfo       map[string]string
	Jottiscanres             map[string]string
	MetaScanres              map[string]string
	AvCaesorAVEngineResult   map[string]string
	AvCaesorAVFileInfoResult map[string]string
	CymonIpInfo              map[string]struct {
		Title       string
		Description string
		ReportedBy  string
		Tag         string
		URL         string
		Hostname    string
		Domain      string
		IP          string
		Country     string
		City        string
	}

	GoogleSafeBrowse       map[string][]string
	Urlquerynetsearch      map[string]string
	ShadowServer           map[string]string
	IBMxForceMalwareReport map[string]string
	IBMxFroceIPReport      map[string]struct {
		CreatedDate        string
		Reason             string
		Company            string
		CIDR               string
		Country            string
		CategoryType       string
		CategoryDescripton string
		ReasonDescription  string
		IP                 string
	}
}

var scanResultStructForTemplate ScanResults

func init() {
	mmsatpl = template.Must(template.ParseFiles("./templates/SandboxDisplay.html"))
	apikeys = threatintelstructs.APIs{}
	scanResultStructForTemplate = ScanResults{}
	scanResultStructForTemplate.Jottiscanres = make(map[string]string)
	scanResultStructForTemplate.Vtscanres = make(map[string]string)
	scanResultStructForTemplate.VtUploadedFileInfo = make(map[string]string)
	scanResultStructForTemplate.MetaScanres = make(map[string]string)
	scanResultStructForTemplate.AvCaesorAVEngineResult = make(map[string]string)
	scanResultStructForTemplate.AvCaesorAVFileInfoResult = make(map[string]string)
	scanResultStructForTemplate.CymonIpInfo = make(map[string]struct {
		Title       string
		Description string
		ReportedBy  string
		Tag         string
		URL         string
		Hostname    string
		Domain      string
		IP          string
		Country     string
		City        string
	})
	scanResultStructForTemplate.IBMxFroceIPReport = make(map[string]struct {
		CreatedDate        string
		Reason             string
		Company            string
		CIDR               string
		Country            string
		CategoryType       string
		CategoryDescripton string
		ReasonDescription  string
		IP                 string
	})
	scanResultStructForTemplate.GoogleSafeBrowse = make(map[string][]string)
	scanResultStructForTemplate.Urlquerynetsearch = make(map[string]string)
	scanResultStructForTemplate.ShadowServer = make(map[string]string)
	scanResultStructForTemplate.IBMxForceMalwareReport = make(map[string]string)
}

func fillapikeys() {
	apifile, err := ioutil.ReadFile("./config/apiconfig.cfg")
	if err != nil {
		fmt.Println(err)
	}
	err = json.Unmarshal(apifile, &apikeys)
	if err != nil {
		fmt.Println(err)
	}

}

func clearhistory(clearmap map[string]string) {
	for k := range clearmap {
		delete(clearmap, k)
	}

}

func clearsafebrosehistory(clearmap map[string][]string) {
	for k := range clearmap {
		delete(clearmap, k)
	}

}

func index(httpwr http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		err := mmsatpl.Execute(httpwr, nil)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		err := req.ParseForm()
		searchval := req.Form.Get("search")
		//filepath := req.Form.Get("filepath")
		//fmt.Println("path " + filepath)

		if strings.Compare(strings.TrimSpace(searchval), "") != 0 {

			clearhistory(scanResultStructForTemplate.Vtscanres)
			clearhistory(scanResultStructForTemplate.VtUploadedFileInfo)
			clearsafebrosehistory(scanResultStructForTemplate.GoogleSafeBrowse)
			clearhistory(scanResultStructForTemplate.Urlquerynetsearch)
			clearhistory(scanResultStructForTemplate.ShadowServer)
			clearhistory(scanResultStructForTemplate.IBMxForceMalwareReport)

			//vtResult = vtResult[:0]
			//vtResult = vtScanner(strings.TrimSpace(searchval))
			if strings.Index(searchval, "http") == 0 {
				finflag := make(chan string)
				go urlquerynet.Urlquerynetsearch(searchval, scanResultStructForTemplate.Urlquerynetsearch, finflag)
				go safebrowse.Getgooglesafebrowseresult(searchval, apikeys.Safebrowse, scanResultStructForTemplate.GoogleSafeBrowse, finflag)
				go virustotal.VtURLScanner(strings.TrimSpace(searchval), scanResultStructForTemplate.Vtscanres, finflag)
				<-finflag
				<-finflag
				<-finflag

			} else {
				finflag := make(chan string)
				//go vtexescanprocess(finflag)
				go virustotal.VtExeScanner(strings.TrimSpace(searchval), scanResultStructForTemplate.Vtscanres, scanResultStructForTemplate.VtUploadedFileInfo, finflag)
				go ibmxforce.XchangeMalwareHashReport(strings.TrimSpace(searchval), apikeys.IBMxForceKey, apikeys.IBMxForcePass, scanResultStructForTemplate.IBMxForceMalwareReport, finflag)
				go shadowserver.Shadowserversearch(strings.TrimSpace(searchval), scanResultStructForTemplate.ShadowServer, finflag)
				<-finflag
				<-finflag
				<-finflag

			}

			/*for k, v := range scanResultStructForTemplate.Vtscanres{
				 fmt.Printf("%s\t\t%s\n ", k,v)
			 }*/
			err = mmsatpl.Execute(httpwr, scanResultStructForTemplate)
			if err != nil {
				fmt.Println(err)
			}
		} else if strings.Compare(strings.TrimSpace(req.Form.Get("iocsearch")), "") != 0 {
			//clear values
			for k := range scanResultStructForTemplate.CymonIpInfo {
				delete(scanResultStructForTemplate.CymonIpInfo, k)
			}
			//clear values
			for k := range scanResultStructForTemplate.IBMxFroceIPReport {
				delete(scanResultStructForTemplate.IBMxFroceIPReport, k)
			}
			searchIPDomain := strings.TrimSpace(req.Form.Get("iocsearch"))
			validIP := regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
			isIP := validIP.MatchString(searchIPDomain)

			finflag := make(chan string)
			go cymonio.Getcymoniotoken(apikeys.CymonUser, apikeys.CymonPassword, finflag)
			<-finflag
			go cymonio.Getdetailsfromcymon(finflag, isIP, searchIPDomain, scanResultStructForTemplate.CymonIpInfo)
			<-finflag
			if isIP {
				go ibmxforce.XchangeIPReport(searchIPDomain, apikeys.IBMxForceKey, apikeys.IBMxForcePass, scanResultStructForTemplate.IBMxFroceIPReport, finflag)
				<-finflag
			}

			err = mmsatpl.Execute(httpwr, scanResultStructForTemplate)
			if err != nil {
				fmt.Println(err)
			}

		} else {

			clearhistory(scanResultStructForTemplate.Jottiscanres)
			clearhistory(scanResultStructForTemplate.AvCaesorAVFileInfoResult)
			clearhistory(scanResultStructForTemplate.AvCaesorAVEngineResult)
			clearhistory(scanResultStructForTemplate.MetaScanres)

			file, handler, err := req.FormFile("upfile")
			if err != nil {
				fmt.Println(err)
				return
			}
			defer file.Close()
			filename := handler.Filename
			if strings.Compare(strings.TrimSpace(filename), "") != 0 {

				f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0666)
				if err != nil {
					fmt.Println(err)
					return
				}
				defer f.Close()

				io.Copy(f, file)
				if err != nil {
					fmt.Println(err)
				}
				finflag := make(chan string)

				go jotti.Jottiscanprocess(file, filename, finflag, apikeys.Jotti, scanResultStructForTemplate.Jottiscanres)
				go avcaesar.Uploadfiletoavcaesar(filename, finflag, scanResultStructForTemplate.AvCaesorAVFileInfoResult, scanResultStructForTemplate.AvCaesorAVEngineResult)
				//go metadefenderfilescan(filename, finflag)
				go metadefender.Metadefenderfilescan(filename, finflag, apikeys.Metadefender, scanResultStructForTemplate.MetaScanres)
				time.Sleep(6000 * time.Millisecond)
				<-finflag
				<-finflag
				<-finflag

				err = mmsatpl.Execute(httpwr, scanResultStructForTemplate)
				if err != nil {
					fmt.Println(err)
				}
			}
		}
	}

}

func main() {
	fillapikeys()
	http.HandleFunc("/", index)
	http.ListenAndServe(":"+apikeys.AppPort, nil)
}
