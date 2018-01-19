package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"./threatintelstructs"
	"github.com/PuerkitoBio/goquery"
)

var mmsatpl *template.Template
var apikeys threatintelstructs.APIs
var vtexeres threatintelstructs.Vtexescanresult
var vturlres threatintelstructs.Vturlscanresult
var jottitoken threatintelstructs.JottiVirusScanToken
var jottijobscanid threatintelstructs.JottiVirusScanFileScanJobID
var jottiScanResult threatintelstructs.JottiVirusScanResult
var metascanDataId threatintelstructs.MetaDefenderDataID
var metascanResult threatintelstructs.MetaDefenderScanResult
var cymonauthtoken threatintelstructs.CymonAuthHead
var cymonIpResult threatintelstructs.CymonIPResult
var googlesafebrowse threatintelstructs.GoogleSafeBrowsing
var ibmxforcemalwarereport threatintelstructs.IBMxForceMalware
var ibmxforceipreport threatintelstructs.IBMxFroceIPReport

var vtResult []byte

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

func shadowserversearch(searchval string, finflag chan string) {
	avresult := make(map[string]string)
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://innocuous.shadowserver.org/api/", nil)
	if err != nil {
		fmt.Println(err)
	}
	qstring := req.URL.Query()
	qstring.Add("query", searchval)
	req.URL.RawQuery = qstring.Encode()
	resp, err3 := client.Do(req)
	if err3 != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	bodybyte, err2 := ioutil.ReadAll(resp.Body)
	if err2 != nil {
		fmt.Println(err)
	}
	var resultstring string
	resultstring = string(bodybyte)
	finalarray := strings.Split(resultstring, "\n")
	if len(finalarray) > 0 {
		for i := range finalarray {
			if strings.Index(finalarray[i], "{") == 0 {
				avresult[strconv.Itoa(i)] = finalarray[i]
				//fmt.Println((finalarray[i]))
			}
		}
		for k := range avresult {
			if strings.Contains(avresult[k], ":") {
				scanResultStructForTemplate.ShadowServer[(strings.Replace(strings.Replace(strings.Split(avresult[k], ":")[0], "\"", "", 2), "{", "", 1))] = (strings.Replace(strings.Replace(strings.Split(avresult[k], ":")[1], "\"", "", 2), "}", "", 1))
			}
		}
	}

	finflag <- "finished shadow server"
}

func getcymoniotoken(finflag chan string) {

	apiURL := "https://api.cymon.io/v2/auth/login"
	var jsonStr = []byte(`{"username":"usr","password":"pass"}`)

	jsonStr = []byte(strings.Replace(string(jsonStr), "usr", apikeys.CymonUser, 1))
	jsonStr = []byte(strings.Replace(string(jsonStr), "pass", apikeys.CymonPassword, 1))
	//Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}

	/*transport := http.Transport{}
	transport.Proxy = http.ProxyURL(proxyUrl)// set proxy
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //set ssl*/

	//if need to set proxy
	//proxyUrl, _ := url.Parse("http://127.0.0.1:8080")
	//client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig:&tls.Config{InsecureSkipVerify: true }}}
	//r, _ := http.NewRequest("POST",urlstr,strings.NewReader(data.Encode()))
	client := &http.Client{}
	req, _ := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonStr))
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body_byte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	json.Unmarshal(body_byte, &cymonauthtoken)
	finflag <- "got token"
	//fmt.Println(cymonauthtoken.Jwt)
}

func getdetailsfromcymon(finflag chan string, isIP bool, cymontoken string, searchval string) string {

	var apiURL string
	if isIP {
		apiURL = "https://api.cymon.io/v2/ioc/search/ip/" + searchval
	} else {
		apiURL = "https://api.cymon.io/v2/ioc/search/domain/" + searchval
	}

	//Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}

	/*transport := http.Transport{}
	transport.Proxy = http.ProxyURL(proxyUrl)// set proxy
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //set ssl*/

	//if need to set proxy
	//proxyUrl, _ := url.Parse("http://127.0.0.1:8080")
	//client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig:&tls.Config{InsecureSkipVerify: true }}}
	client := &http.Client{}
	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Add("Authorization", cymontoken)

	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body_byte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	json.Unmarshal(body_byte, &cymonIpResult)
	//fmt.Println(string(body_byte))
	finflag <- "got cymonresult"
	return string(body_byte)
}

func uploadfiletoavcaesar(filename string, finflag chan string) {

	apiURL := "https://avcaesar.malware.lu/"
	resource := "/sample/upload"
	u, _ := url.ParseRequestURI(apiURL)
	u.Path = resource
	urlstr := u.String()
	//fmt.Println(urlstr)

	fh, err := os.Open(filename)
	if err != nil {
		fmt.Println("error opening file")
	}
	defer fh.Close()
	bodybuff := &bytes.Buffer{}
	bodywriter := multipart.NewWriter(bodybuff)
	filewriter, err := bodywriter.CreateFormFile("file", filepath.Base(filename))
	if err != nil {
		fmt.Println("error writing to file")
	}
	_, err = io.Copy(filewriter, fh)
	if err != nil {
		fmt.Println(err)
	}

	bodywriter.Close()

	req, err := http.NewRequest("POST", urlstr, bodybuff)
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Add("Accept-Language", "en-US,en;q=0.5")
	req.Header.Add("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Content-Type", bodywriter.FormDataContentType())

	//proxyUrl, _ := url.Parse("http://127.0.0.1:8080")
	//client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig:&tls.Config{InsecureSkipVerify: true }}}
	//client := &http.Client{}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}

	//fmt.Printf("Uploading .......")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Printf("............Done.\n")
	//fmt.Printf("Status Code : . %d\n",resp.StatusCode)
	defer resp.Body.Close()
	body_byte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	if err != nil {
		fmt.Println(err)
	}

	finalvalue := string(body_byte)
	finalvalue = finalvalue + "</p>"

	editedval := bytes.NewReader([]byte(finalvalue))
	doc, err := goquery.NewDocumentFromReader(editedval)
	linkval, _ := doc.Find("a").Attr("href")
	//fmt.Println("Link from response : " + linkval)
	actualURL, _ := url.Parse(apiURL)
	actualURL.Path = linkval
	crawlavcaesorresultforAV(actualURL.String())
	crawlavcaesorresultTables(actualURL.String())
	prepareavcaesorfileinfo()
	finflag <- "finished"

}

func crawlavcaesorresultforAV(linkval string) {
	doc, err := goquery.NewDocument(linkval)
	if err != nil {
		fmt.Println(err)
	}
	// use CSS selector found with the browser inspector
	// for each, use index and item
	doc.Find("#antivirus tr td").Each(func(index int, item *goquery.Selection) {

		propname, _ := item.Attr("class")
		if propname == "name" {
			propname = item.Text()
			if strings.Compare(strings.TrimSpace(strings.Split(item.Next().Text(), "\t")[0]), "-") != 0 &&
				strings.Compare(strings.TrimSpace(strings.Split(item.Next().Text(), "\t")[0]), "") != 0 {
				scanResultStructForTemplate.AvCaesorAVEngineResult[propname] = strings.TrimSpace(strings.Split(item.Next().Text(), "\t")[0])
			}
		}
	})
}

func crawlavcaesorresultTables(linkval string) {

	doc, err := goquery.NewDocument(linkval)
	if err != nil {
		fmt.Println(err)
	}
	// use CSS selector found with the browser inspector
	// for each, use index and item
	doc.Find("table tr th").Each(func(index int, item *goquery.Selection) {
		key := item.Text()
		val := item.Next().Text()
		if strings.Compare(strings.TrimSpace(key), "PEID SysReveal Database") == 0 {
			scanResultStructForTemplate.AvCaesorAVFileInfoResult["Compiler"] = strings.TrimSpace(val)
		} else {
			scanResultStructForTemplate.AvCaesorAVFileInfoResult[key] = strings.TrimSpace(val)
		}

	})
}

func getjottifilescanjobid() []byte {

	apiURL := "https://virusscan.jotti.org"
	resource := "/api/filescanjob/createscantoken"
	u, _ := url.ParseRequestURI(apiURL)
	u.Path = resource
	urlstr := u.String()
	//fmt.Println(urlstr)

	//Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)}

	/*transport := http.Transport{}
	transport.Proxy = http.ProxyURL(proxyUrl)// set proxy
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //set ssl*/

	//if need to set proxy
	//proxyUrl, _ := url.Parse("http://127.0.0.1:8080")
	//client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig:&tls.Config{InsecureSkipVerify: true }}}
	//r, _ := http.NewRequest("POST",urlstr,strings.NewReader(data.Encode()))
	client := &http.Client{}
	req, _ := http.NewRequest("POST", urlstr, nil)
	req.Header.Add("Authorization", "Key "+apikeys.Jotti)
	req.Header.Add("Accept", "application/vnd.filescanjob-api.v2+json")
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body_byte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	return body_byte
	//fmt.Println(string(body_byte))
}
func getjottiscannedresult(jobscanid string) []byte {

	jobidurl := "https://virusscan.jotti.org/api/filescanjob/getjobstatus/" + jobscanid
	req, _ := http.NewRequest("GET", jobidurl, nil)
	req.Header.Add("Authorization", "Key "+apikeys.Jotti)
	req.Header.Add("Accept", "application/vnd.filescanjob-api.v2+json")
	req.Header.Add("Content-Type", "application/json")
	//proxyUrl, _ := url.Parse("http://127.0.0.1:8080")
	//client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig:&tls.Config{InsecureSkipVerify: true }}}
	//fmt.Println(req.URL.String())
	client := &http.Client{}
	resp, err := client.Do(req)
	//resp, err := http.Get("https://www.virustotal.com/ui/search?query=cc5c1ceeabf310b66e750f3e7fa4e091&relationships[url]=network_location%2Clast_serving_ip_address&relationships[comment]=author%2Citem")
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body_byte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}

	return (body_byte)

}

func uploadfiletojottiusingmultipartformdata(filecontent multipart.File, filename string, desturl string, token string) []byte {

	//fmt.Println("token " + token)
	/*fh, err := os.Open(filename)
	if err != nil {
		fmt.Println("error opening file")
	}
	defer fh.Close()*/
	bodybuff := &bytes.Buffer{}
	bodywriter := multipart.NewWriter(bodybuff)

	filewriter, err := bodywriter.CreateFormFile("file", filepath.Base(filename))
	if err != nil {
		fmt.Println("error writing to file")
	}
	_, err = io.Copy(filewriter, filecontent)
	if err != nil {
		fmt.Println(err)
	}

	formfield, formfielderr := bodywriter.CreateFormField("scanToken")
	if formfielderr != nil {
		fmt.Println(err)
	}
	formfield.Write([]byte(token))

	bodywriter.Close()
	//contentType := bodywriter.FormDataContentType()
	req, err := http.NewRequest("POST", desturl, bodybuff)
	req.Header.Add("Authorization", "Key "+apikeys.Jotti)
	req.Header.Add("Accept", "application/vnd.filescanjob-api.v2+json")
	req.Header.Set("Content-Type", bodywriter.FormDataContentType())
	//proxyUrl, _ := url.Parse("http://127.0.0.1:8080")
	//client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig:&tls.Config{InsecureSkipVerify: true }}}
	client := &http.Client{}
	//fmt.Printf("Uploading Jotti.......")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Printf("............Jotti Done.\n")
	defer resp.Body.Close()
	body_byte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	//fmt.Println("Jotti scan result is : \n")
	//fmt.Println(string(body_byte))
	return body_byte
}

func uploadfiletojotti(filename string, desturl string, token string) []byte {

	//fmt.Println("token " + token)
	fh, err := os.Open(filename)
	if err != nil {
		fmt.Println("error opening file")
	}
	defer fh.Close()

	bodybuff := &bytes.Buffer{}
	bodywriter := multipart.NewWriter(bodybuff)
	filewriter, err := bodywriter.CreateFormFile("file", filepath.Base(filename))
	if err != nil {
		fmt.Println("error writing to file")
	}
	_, err = io.Copy(filewriter, fh)
	if err != nil {
		fmt.Println(err)
	}

	formfield, formfielderr := bodywriter.CreateFormField("scanToken")
	if formfielderr != nil {
		fmt.Println(err)
	}
	formfield.Write([]byte(token))

	bodywriter.Close()
	//contentType := bodywriter.FormDataContentType()

	req, err := http.NewRequest("POST", desturl, bodybuff)
	req.Header.Add("Authorization", "Key "+apikeys.Jotti)
	req.Header.Add("Accept", "application/vnd.filescanjob-api.v2+json")
	req.Header.Set("Content-Type", bodywriter.FormDataContentType())
	//proxyUrl, _ := url.Parse("http://127.0.0.1:8080")
	//client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig:&tls.Config{InsecureSkipVerify: true }}}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body_byte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	return body_byte
}

func vtScanner(searchvalue string) []byte {

	req, _ := http.NewRequest("GET", "https://www.virustotal.com/ui/search", nil)
	qstring := req.URL.Query()
	qstring.Add("query", searchvalue)
	qstring.Add("relationships[url]", "network_location,last_serving_ip_address")
	qstring.Add("relationships[comment]=", "author,item")
	req.URL.RawQuery = qstring.Encode()
	client := &http.Client{}
	resp, err := client.Do(req)

	//resp, err := http.Get("https://www.virustotal.com/ui/search?query=cc5c1ceeabf310b66e750f3e7fa4e091&relationships[url]=network_location%2Clast_serving_ip_address&relationships[comment]=author%2Citem")
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body_byte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	return (body_byte)
}
func checkandaddtoresult(avname string, category string, result interface{}) {
	switch category {
	case "malicious", "phishing":
		scanResultStructForTemplate.Vtscanres[avname] = fmt.Sprintf("%v", result)
	}
}
func metadefenderfilescan(filename string, finflag chan string) {

	fh, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
	}
	defer fh.Close()
	bodybuff := &bytes.Buffer{}
	bodywriter := multipart.NewWriter(bodybuff)

	filewriter, err := bodywriter.CreateFormFile("file", filepath.Base(filename))
	if err != nil {
		fmt.Println("error writing to file")
	}
	_, err = io.Copy(filewriter, fh)
	if err != nil {
		fmt.Println(err)
	}

	bodywriter.Close()
	scanreq, scanreqerr := http.NewRequest("POST", "https://api.metadefender.com/v2/file", bodybuff)
	if scanreqerr != nil {
		fmt.Println(scanreqerr)
	}
	scanreq.Header.Add("apikey", apikeys.Metadefender)
	scanreq.Header.Add("Content-Type", bodywriter.FormDataContentType())

	client := &http.Client{}
	//fmt.Println("Uploading .........")
	resp, uploaderr := client.Do(scanreq)
	if uploaderr != nil {
		fmt.Println(uploaderr)
	}
	//fmt.Println(" .........Done!")
	defer resp.Body.Close()

	respBodyBytes, _ := ioutil.ReadAll(resp.Body)
	//fmt.Println(string(respBodyBytes))
	_ = json.Unmarshal(respBodyBytes, &metascanDataId)
	finflag <- "finishedmetadef"

}

func getmetadefenderfilescanresult(dataid string) []byte {
	//https://api.metadefender.com/v2/file/+dataid
	scanreq, dataiderr := http.NewRequest("GET", "https://api.metadefender.com/v2/file/"+dataid, nil)
	scanreq.Header.Add("apikey", apikeys.Metadefender)
	if dataiderr != nil {
		fmt.Println(dataiderr)
	}
	client := &http.Client{}
	resp, uploaderr := client.Do(scanreq)
	if uploaderr != nil {
		fmt.Println(uploaderr)
	}
	defer resp.Body.Close()

	//fmt.Println("scan result")
	respBodyBytes, _ := ioutil.ReadAll(resp.Body)
	//fmt.Println(string(respBodyBytes))
	return respBodyBytes

}
func jottiscanprocess(file multipart.File, filename string, finflag chan string) {

	jottitoken = threatintelstructs.JottiVirusScanToken{}
	err := json.Unmarshal(getjottifilescanjobid(), &jottitoken)
	if err != nil {
		fmt.Println(err)
	}
	jottijobscanid = threatintelstructs.JottiVirusScanFileScanJobID{}
	errjobid := json.Unmarshal(uploadfiletojotti(strings.TrimSpace(filename), "https://virusscan.jotti.org/api/filescanjob/v2/createjob", jottitoken.ScanToken), &jottijobscanid)
	if errjobid != nil {
		fmt.Println(errjobid)
	}

	jottiScanResult = threatintelstructs.JottiVirusScanResult{}
	time.Sleep(4000 * time.Millisecond)
	errscanres := json.Unmarshal(getjottiscannedresult(jottijobscanid.FileScanJobID), &jottiScanResult)
	if errscanres != nil {
		fmt.Println(errscanres)
	}

	if len(jottiScanResult.ScanJob.ScannerResults) > 0 {
		for i := range jottiScanResult.ScanJob.ScannerResults {
			if strings.Compare(strings.TrimSpace(jottiScanResult.ScanJob.ScannerResults[i].MalwareName), "") > 0 {
				scanResultStructForTemplate.Jottiscanres[jottiScanResult.ScanJob.ScannerResults[i].ScannerName] = jottiScanResult.ScanJob.ScannerResults[i].MalwareName
			}
		}
	}
	finflag <- "finishedjotti"

}

//parmas removed for testing {file multipart.File, filename string}
func metadefenderscanprocess() {

	/*datascaniderr := json.Unmarshal(metadefenderfilescan(file,filename),&metascanDataId )
	if datascaniderr != nil {
		fmt.Println(datascaniderr)
	}
	time.Sleep(4000 * time.Millisecond)
	fmt.Printf("Data ID : %s", metascanDataId.DataID)
	metadefreserr := json.Unmarshal(getmetadefenderfilescanresult(metascanDataId.DataID),&metascanResult)
	if metadefreserr != nil {
		fmt.Println(metadefreserr)
	}*/

	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.Antiy.ThreatFound) != "" {
		scanResultStructForTemplate.MetaScanres["Antiy"] = metascanResult.ScanResults.ScanDetails.Antiy.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.TrendMicro.ThreatFound) != "" {
		scanResultStructForTemplate.MetaScanres["TrendMicro"] = metascanResult.ScanResults.ScanDetails.TrendMicro.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.BitDefender.ThreatFound) != "" {
		scanResultStructForTemplate.MetaScanres["BitDefender"] = metascanResult.ScanResults.ScanDetails.BitDefender.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.AVG.ThreatFound) != "" {
		scanResultStructForTemplate.MetaScanres["AVG"] = metascanResult.ScanResults.ScanDetails.AVG.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.CYREN.ThreatFound) != "" {
		scanResultStructForTemplate.MetaScanres["Cyren"] = metascanResult.ScanResults.ScanDetails.CYREN.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.Fortinet.ThreatFound) != "" {
		scanResultStructForTemplate.MetaScanres["Fortinet"] = metascanResult.ScanResults.ScanDetails.Fortinet.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.Ikarus.ThreatFound) != "" {
		scanResultStructForTemplate.MetaScanres["Ikarus"] = metascanResult.ScanResults.ScanDetails.Ikarus.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.K7.ThreatFound) != "" {
		scanResultStructForTemplate.MetaScanres["K7"] = metascanResult.ScanResults.ScanDetails.K7.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.McAfee.ThreatFound) != "" {
		scanResultStructForTemplate.MetaScanres["McAfee"] = metascanResult.ScanResults.ScanDetails.McAfee.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.QuickHeal.ThreatFound) != "" {
		scanResultStructForTemplate.MetaScanres["QuickHeal"] = metascanResult.ScanResults.ScanDetails.QuickHeal.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.Sophos.ThreatFound) != "" {
		scanResultStructForTemplate.MetaScanres["Sophos"] = metascanResult.ScanResults.ScanDetails.Sophos.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.TotalDefense.ThreatFound) != "" {
		scanResultStructForTemplate.MetaScanres["TotalDefense"] = metascanResult.ScanResults.ScanDetails.TotalDefense.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.Symantec.ThreatFound) != "" {
		scanResultStructForTemplate.MetaScanres["Symantec"] = metascanResult.ScanResults.ScanDetails.Symantec.ThreatFound
	}
	if strings.TrimSpace(metascanResult.ScanResults.ScanDetails.ThreatTrack.ThreatFound) != "" {
		scanResultStructForTemplate.MetaScanres["ThreatTrack"] = metascanResult.ScanResults.ScanDetails.ThreatTrack.ThreatFound
	}
}

func buildVTURLresult() {
	checkandaddtoresult("AlienVault", vturlres.Data[0].Attributes.LastAnalysisResults.AlienVault.Category, vturlres.Data[0].Attributes.LastAnalysisResults.AlienVault.Result)
	checkandaddtoresult("Avira", vturlres.Data[0].Attributes.LastAnalysisResults.Avira.Category, vturlres.Data[0].Attributes.LastAnalysisResults.Avira.Result)
	checkandaddtoresult("BitDefender", vturlres.Data[0].Attributes.LastAnalysisResults.BitDefender.Category, vturlres.Data[0].Attributes.LastAnalysisResults.BitDefender.Result)
	checkandaddtoresult("ComodoSiteInsp", vturlres.Data[0].Attributes.LastAnalysisResults.ComodoSiteInspector.Category, vturlres.Data[0].Attributes.LastAnalysisResults.ComodoSiteInspector.Result)
	checkandaddtoresult("DrWeb", vturlres.Data[0].Attributes.LastAnalysisResults.DrWeb.Category, vturlres.Data[0].Attributes.LastAnalysisResults.DrWeb.Result)
	checkandaddtoresult("DNS8", vturlres.Data[0].Attributes.LastAnalysisResults.DNS8.Category, vturlres.Data[0].Attributes.LastAnalysisResults.DNS8.Result)
	checkandaddtoresult("ESET", vturlres.Data[0].Attributes.LastAnalysisResults.ESET.Category, vturlres.Data[0].Attributes.LastAnalysisResults.ESET.Result)
	checkandaddtoresult("Fortinet", vturlres.Data[0].Attributes.LastAnalysisResults.Fortinet.Category, vturlres.Data[0].Attributes.LastAnalysisResults.Fortinet.Result)
	checkandaddtoresult("GoogleSafeBrows", vturlres.Data[0].Attributes.LastAnalysisResults.GoogleSafebrowsing.Category, vturlres.Data[0].Attributes.LastAnalysisResults.GoogleSafebrowsing.Result)
	checkandaddtoresult("Kaspersky", vturlres.Data[0].Attributes.LastAnalysisResults.Kaspersky.Category, vturlres.Data[0].Attributes.LastAnalysisResults.Kaspersky.Result)
	checkandaddtoresult("MalwareBytesHP", vturlres.Data[0].Attributes.LastAnalysisResults.MalwarebytesHpHosts.Category, vturlres.Data[0].Attributes.LastAnalysisResults.MalwarebytesHpHosts.Result)
	checkandaddtoresult("MalwareDomBlck", vturlres.Data[0].Attributes.LastAnalysisResults.MalwareDomainBlocklist.Category, vturlres.Data[0].Attributes.LastAnalysisResults.MalwareDomainBlocklist.Result)
	checkandaddtoresult("MalwareDomain", vturlres.Data[0].Attributes.LastAnalysisResults.MalwareDomainList.Category, vturlres.Data[0].Attributes.LastAnalysisResults.MalwareDomainList.Result)
	checkandaddtoresult("NetCraft", vturlres.Data[0].Attributes.LastAnalysisResults.Netcraft.Category, vturlres.Data[0].Attributes.LastAnalysisResults.Netcraft.Result)
	checkandaddtoresult("OpenPhish", vturlres.Data[0].Attributes.LastAnalysisResults.OpenPhish.Category, vturlres.Data[0].Attributes.LastAnalysisResults.OpenPhish.Result)
	checkandaddtoresult("PhishTank", vturlres.Data[0].Attributes.LastAnalysisResults.Phishtank.Category, vturlres.Data[0].Attributes.LastAnalysisResults.Phishtank.Result)
	checkandaddtoresult("PhishLabs", vturlres.Data[0].Attributes.LastAnalysisResults.PhishLabs.Category, vturlres.Data[0].Attributes.LastAnalysisResults.PhishLabs.Result)
	checkandaddtoresult("SophosAV", vturlres.Data[0].Attributes.LastAnalysisResults.Sophos.Category, vturlres.Data[0].Attributes.LastAnalysisResults.Sophos.Result)
	checkandaddtoresult("Spam404", vturlres.Data[0].Attributes.LastAnalysisResults.Spam404.Category, vturlres.Data[0].Attributes.LastAnalysisResults.Spam404.Result)
	checkandaddtoresult("ZeusTracker", vturlres.Data[0].Attributes.LastAnalysisResults.ZeusTracker.Category, vturlres.Data[0].Attributes.LastAnalysisResults.ZeusTracker.Result)
}

func buildVTEXEresult() {

	checkandaddtoresult("Avira", vtexeres.Data[0].Attributes.LastAnalysisResults.Avira.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Avira.Result)
	checkandaddtoresult("Avast", vtexeres.Data[0].Attributes.LastAnalysisResults.Avast.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Avast.Result)
	checkandaddtoresult("AVG", vtexeres.Data[0].Attributes.LastAnalysisResults.AVG.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.AVG.Result)
	checkandaddtoresult("BitDefender", vtexeres.Data[0].Attributes.LastAnalysisResults.BitDefender.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.BitDefender.Result)
	checkandaddtoresult("CrowdStrike", vtexeres.Data[0].Attributes.LastAnalysisResults.CrowdStrike.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.CrowdStrike.Result)
	checkandaddtoresult("Cylance", vtexeres.Data[0].Attributes.LastAnalysisResults.Cylance.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Cylance.Result)
	checkandaddtoresult("CyberReason", vtexeres.Data[0].Attributes.LastAnalysisResults.Cybereason.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Cybereason.Result)
	checkandaddtoresult("EndGame", vtexeres.Data[0].Attributes.LastAnalysisResults.Endgame.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Endgame.Result)
	checkandaddtoresult("ESETNode", vtexeres.Data[0].Attributes.LastAnalysisResults.ESETNOD32.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.ESETNOD32.Result)
	checkandaddtoresult("Fortinet", vtexeres.Data[0].Attributes.LastAnalysisResults.Fortinet.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Fortinet.Result)
	checkandaddtoresult("Kaspersky", vtexeres.Data[0].Attributes.LastAnalysisResults.Kaspersky.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Kaspersky.Result)
	checkandaddtoresult("Malwarebytes", vtexeres.Data[0].Attributes.LastAnalysisResults.Malwarebytes.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Malwarebytes.Result)
	checkandaddtoresult("McAfee", vtexeres.Data[0].Attributes.LastAnalysisResults.McAfee.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.McAfee.Result)
	checkandaddtoresult("McAfeeGWEd", vtexeres.Data[0].Attributes.LastAnalysisResults.McAfeeGWEdition.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.McAfeeGWEdition.Result)
	checkandaddtoresult("Sophos", vtexeres.Data[0].Attributes.LastAnalysisResults.Sophos.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Sophos.Result)
	checkandaddtoresult("Symantec", vtexeres.Data[0].Attributes.LastAnalysisResults.Symantec.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.Symantec.Result)
	checkandaddtoresult("TrendMicro", vtexeres.Data[0].Attributes.LastAnalysisResults.TrendMicro.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.TrendMicro.Result)
	checkandaddtoresult("ZoneAlarm", vtexeres.Data[0].Attributes.LastAnalysisResults.ZoneAlarm.Category, vtexeres.Data[0].Attributes.LastAnalysisResults.ZoneAlarm.Result)

}

func vturlscanprocess() {

	vturlres = threatintelstructs.Vturlscanresult{}
	err := json.Unmarshal(vtResult, &vturlres)
	if err != nil {
		fmt.Println(err)
		//fmt.Println("")
	}
	if len(vturlres.Data) > 0 {
		buildVTURLresult()
	}
}
func vtexescanprocess(finflag chan string) {
	vtexeres = threatintelstructs.Vtexescanresult{}
	err := json.Unmarshal(vtResult, &vtexeres)
	if err != nil {
		fmt.Println("")
	}
	if len(vtexeres.Data) > 0 {
		buildVTEXEresult()
		updatevtfileinfomap()
	}
	finflag <- "vt exe scan finished"
}

func updatevtfileinfomap() {
	scanResultStructForTemplate.VtUploadedFileInfo["PEType"] = vtexeres.Data[0].Attributes.Exiftool.PEType
	scanResultStructForTemplate.VtUploadedFileInfo["FileType"] = vtexeres.Data[0].Attributes.Exiftool.FileType
	scanResultStructForTemplate.VtUploadedFileInfo["EntryPoint"] = vtexeres.Data[0].Attributes.Exiftool.EntryPoint
	scanResultStructForTemplate.VtUploadedFileInfo["FileVersion"] = vtexeres.Data[0].Attributes.Exiftool.FileVersion
	scanResultStructForTemplate.VtUploadedFileInfo["OriginalFileName"] = vtexeres.Data[0].Attributes.Exiftool.OriginalFileName
	scanResultStructForTemplate.VtUploadedFileInfo["Sha256"] = vtexeres.Data[0].Attributes.Sha256
	scanResultStructForTemplate.VtUploadedFileInfo["Md5"] = vtexeres.Data[0].Attributes.Md5
}

func prepareavcaesorfileinfo() {
	for k, _ := range scanResultStructForTemplate.AvCaesorAVFileInfoResult {

		switch strings.TrimSpace(k) {
		case "Antivirus", "Address", "Definition date", "EXE:EntryPoint", "EXE:FileFlags", "EXE:FileFlagsMask", "EXE:FileOS", "EXE:FileSubtype",
			"EXE:FileVersionNumber", "EXE:ImageVersion", "First seen", "File:FileModifyDate", "Entropy", "EXE:UninitializedDataSize",
			"EXE:PEType", "PEID BobSoft Database", "PEID Panda Database", "PEID SANS Database", "Position", "SizeOfRawData", "Url", "VirtualAddress",
			"Misc_VirtualSize", "Name", "Result", "EXE:MachineType", "EXE:Subsystem", "EXE:SubsystemVersion", "EXE:TimeStamp", "Number of RVA and Sizes",
			"Optional Header", "File:FileSize", "File:FileType", "Flags":
			delete(scanResultStructForTemplate.AvCaesorAVFileInfoResult, k)
		}

	}
}

func getgooglesafebrowseresult(urltosearch string, finflag chan string) {

	query := "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + apikeys.Safebrowse

	var jsonStr = []byte(`{
    "client": {
      "clientId":      "threatintel",
      "clientVersion": "1.5.2"
    },
    "threatInfo": {
      "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING"],
      "platformTypes":    ["WINDOWS"],
      "threatEntryTypes": ["URL"],
      "threatEntries": [
        {"url": "replace"}
      ]
    }
  }`)

	jsonStr = []byte(strings.Replace(string(jsonStr), "replace", urltosearch, 1))

	client := &http.Client{}
	req, _ := http.NewRequest("POST", query, bytes.NewBuffer(jsonStr))
	req.Header.Add("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()
	body_byte, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
	}
	googlesafebrowse = threatintelstructs.GoogleSafeBrowsing{}
	err = json.Unmarshal(body_byte, &googlesafebrowse)
	if err != nil {
		fmt.Println(err)
	}

	finflag <- "finished safebrowse"
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

func urlquerynetsearch(tosearch string, finflag chan string) {
	var mainurl string
	mainurl = "http://www.urlquery.net/search"
	req, _ := http.NewRequest("GET", mainurl, nil)
	qstring := req.URL.Query()
	qstring.Add("q", tosearch)
	req.URL.RawQuery = qstring.Encode()
	client := &http.Client{}
	resp, _ := client.Do(req)
	defer resp.Body.Close()
	doc, goqueryerr := goquery.NewDocumentFromResponse(resp)
	if goqueryerr != nil {
		fmt.Println(goqueryerr)
	}
	resultlink, _ := doc.Find("table tr td").Find("a").Attr("href")

	mainlink, _ := url.ParseRequestURI(mainurl)
	mainlink.Path = resultlink
	//fmt.Printf("Main link : %s \n",mainlink.String())
	newreq, _ := http.NewRequest("GET", mainlink.String(), nil)
	client2 := &http.Client{}
	newresp, _ := client2.Do(newreq)
	defer newresp.Body.Close()
	//bodybyte , _ := ioutil.ReadAll(newresp.Body)
	//fmt.Println(string(bodybyte))

	doc2, goqueryerr2 := goquery.NewDocumentFromResponse(newresp)
	if goqueryerr2 != nil {
		fmt.Println(goqueryerr)
	}
	doc2.Find("table tbody tr").Each(func(index int, item *goquery.Selection) {

		key := strings.TrimSpace(item.Find(".odd_heading").Text())
		//fmt.Printf("Key val is %s", key)
		switch key {
		case "ASN", "Pool", "Report completed":
			key = ""
		}

		if strings.Contains(key, "Access Level") || strings.Contains(key, "Referer") || strings.Contains(key, "Status") {
			key = ""
		}

		val := item.Find(".odd_heading").Next().Text()

		if key != "" {
			//fmt.Printf("Key  : %s\t\tValue : %s \n", key, val)
			if strings.Contains(key, "Fortinet") || strings.Contains(key, "Suricata") || strings.Contains(key, "OpenPhish") &&
				!strings.Contains(val, "No alerts detected") {
				val = item.Find(".odd_heading").Next().Find("table tbody").Find("tr").Find("td").Last().Text()
			}
			scanResultStructForTemplate.Urlquerynetsearch[key] = strings.TrimSpace(val)
		}

		key = strings.TrimSpace(item.Find(".even_heading").Text())
		val = item.Find(".even_heading").Next().Text()
		if key != "" {
			//fmt.Printf("Key  : %s\t\tValue : %s \n", key, val)
			val = strings.TrimRight(val, "\n\r")
			scanResultStructForTemplate.Urlquerynetsearch[key] = strings.TrimSpace(val)
		}
	})

	for k := range scanResultStructForTemplate.Urlquerynetsearch {
		if strings.Contains(k, "Access Level") || strings.Contains(k, "Referer") || strings.Contains(k, "Status") {
			delete(scanResultStructForTemplate.Urlquerynetsearch, k)
		}
	}

	finflag <- "finsihed urlquery.net"
	/*for k, v := range scanResultStructForTemplate.Urlquerynetsearch {
		fmt.Printf("%s\t\t%s\n",k, v)
	}*/
}

func ibmxforcexchangemalwarehash(searchval string, finflag chan string) {
	ibmapikey := apikeys.IBMxForceKey
	ibmapipass := apikeys.IBMxForcePass
	apiurl := "https://api.xforce.ibmcloud.com/"
	malwareresouce := "/malware/" + searchval
	finalurl, _ := url.ParseRequestURI(apiurl)
	finalurl.Path = malwareresouce
	urltosearch := finalurl.String()
	//fmt.Println(urltosearch)
	req, _ := http.NewRequest("GET", urltosearch, nil)
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(ibmapikey, ibmapipass)
	ibmclient := &http.Client{}
	resp, _ := ibmclient.Do(req)
	defer resp.Body.Close()
	resp_body_byte, _ := ioutil.ReadAll(resp.Body)
	//fmt.Println(string(resp_body_byte))

	ibmxforcemalwarereport = threatintelstructs.IBMxForceMalware{}
	var malwarefamily string
	var malwarefamilies []string
	json.Unmarshal(resp_body_byte, &ibmxforcemalwarereport)
	//scanResultStructForTemplate.IBMxForceMalwareReport["Detection Coverage"] = strconv.Itoa(ibmxforcemalwarereport.Malware.Origins.External.DetectionCoverage)
	malwarefamilies = ibmxforcemalwarereport.Malware.Origins.External.Family
	if len(malwarefamilies) == 1 {
		scanResultStructForTemplate.IBMxForceMalwareReport["MalwareFamily"] = malwarefamilies[0]
	} else if len(malwarefamilies) > 1 {
		for i := range malwarefamilies {
			//fmt.Println(malwarefamilies[i])
			malwarefamily += malwarefamilies[i] + ","
		}
	}
	scanResultStructForTemplate.IBMxForceMalwareReport["MalwareFamily"] = malwarefamily
	scanResultStructForTemplate.IBMxForceMalwareReport["Risk"] = ibmxforcemalwarereport.Malware.Risk
	/*for k, v := range scanResultStructForTemplate.IBMxForceMalwareReport {
		fmt.Printf("%s --- %s", scanResultStructForTemplate.IBMxForceMalwareReport[k], scanResultStructForTemplate.IBMxForceMalwareReport[v])
	}*/
	finflag <- "ibm malware search finished"
	//fmt.Println(string(resp_body_byte))

}

func ibmxforcexchangeip(searchval string, finflag chan string) {
	ibmapikey := apikeys.IBMxForceKey
	ibmapipass := apikeys.IBMxForcePass
	apiurl := "https://api.xforce.ibmcloud.com/"
	//malwareresouce := "/malware/" + searchval
	ipreport := "/ipr/" + searchval
	//ipmalwarereport := "/ipr/malware/" + searchval
	finalurl, _ := url.ParseRequestURI(apiurl)
	finalurl.Path = ipreport
	urltosearch := finalurl.String()
	//fmt.Println(urltosearch)
	req, _ := http.NewRequest("GET", urltosearch, nil)
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(ibmapikey, ibmapipass)
	ibmclient := &http.Client{}
	resp, _ := ibmclient.Do(req)
	defer resp.Body.Close()
	resp_body_byte, _ := ioutil.ReadAll(resp.Body)
	ibmxforceipreport = threatintelstructs.IBMxFroceIPReport{}
	err := json.Unmarshal(resp_body_byte, &ibmxforceipreport)
	if err != nil {
		fmt.Println(err)
	}
	type ibmiphistory struct {
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

	var ipresult ibmiphistory

	for index, ipInfo := range ibmxforceipreport.History {
		ipresult.CreatedDate = ipInfo.Created.Format("2006-01-02 15:04:05")
		ipresult.Reason = ipInfo.Reason
		ipresult.Company = ipInfo.Asns.Num5048.Company
		ipresult.Country = ipInfo.Geo.Country
		ipresult.CIDR = strconv.Itoa(ipInfo.Asns.Num5048.Cidr)
		ipresult.IP = ipInfo.IP
		for k := range ipInfo.Cats {
			ipresult.CategoryType += k
		}
		for k, v := range ipInfo.CategoryDescriptions {
			ipresult.CategoryDescripton += k + ". " + v
		}
		ipresult.Reason = ipInfo.ReasonDescription
		scanResultStructForTemplate.IBMxFroceIPReport[strconv.Itoa(index)] = ipresult
	}

	for index, ipInfo := range ibmxforceipreport.Subnets {
		ipresult.CreatedDate = ipInfo.Created.Format("2006-01-02 15:04:05")
		ipresult.Reason = ipInfo.Reason
		ipresult.Company = ipInfo.Asns.Num5048.Company
		ipresult.Country = ipInfo.Geo.Country
		ipresult.CIDR = strconv.Itoa(ipInfo.Asns.Num5048.Cidr)
		for k := range ipInfo.Cats {
			ipresult.CategoryType += k
		}
		for k, v := range ipInfo.CategoryDescriptions {
			ipresult.CategoryDescripton += k + ". " + v
		}
		ipresult.Reason = ipInfo.ReasonDescription
		scanResultStructForTemplate.IBMxFroceIPReport[strconv.Itoa(index)] = ipresult
	}
	finflag <- "ibm ip report finished"
	//fmt.Println(string(resp_body_byte))

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

			//clear values
			for k := range scanResultStructForTemplate.Vtscanres {
				delete(scanResultStructForTemplate.Vtscanres, k)
			}

			//clear values
			for k := range scanResultStructForTemplate.VtUploadedFileInfo {
				delete(scanResultStructForTemplate.VtUploadedFileInfo, k)
			}

			//clear google safe browse values
			for k := range scanResultStructForTemplate.GoogleSafeBrowse {
				delete(scanResultStructForTemplate.GoogleSafeBrowse, k)
			}

			//clear  urlquerynet
			for k := range scanResultStructForTemplate.Urlquerynetsearch {
				delete(scanResultStructForTemplate.Urlquerynetsearch, k)
			}

			//clear shadowserver
			for k := range scanResultStructForTemplate.ShadowServer {
				delete(scanResultStructForTemplate.ShadowServer, k)
			}

			//clear
			for k := range scanResultStructForTemplate.IBMxForceMalwareReport {
				delete(scanResultStructForTemplate.IBMxForceMalwareReport, k)
			}

			//vtResult = vtResult[:0]
			vtResult = vtScanner(strings.TrimSpace(searchval))
			if strings.Index(searchval, "http") == 0 {
				finflag := make(chan string)
				go urlquerynetsearch(searchval, finflag)
				go getgooglesafebrowseresult(searchval, finflag)
				<-finflag
				<-finflag
				if len(googlesafebrowse.Matches) > 0 {
					scanResultStructForTemplate.GoogleSafeBrowse["SafeBrowse"] = []string{googlesafebrowse.Matches[0].ThreatType, googlesafebrowse.Matches[0].PlatformType, googlesafebrowse.Matches[0].Threat.URL}
				}
				vturlscanprocess()

			} else {
				finflag := make(chan string)
				go vtexescanprocess(finflag)
				go ibmxforcexchangemalwarehash(strings.TrimSpace(searchval), finflag)
				go shadowserversearch(strings.TrimSpace(searchval), finflag)
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
			type resulttoprint struct {
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

			var ipresult resulttoprint
			finflag := make(chan string)
			go getcymoniotoken(finflag)
			<-finflag
			go getdetailsfromcymon(finflag, isIP, cymonauthtoken.Jwt, searchIPDomain)
			<-finflag
			if isIP {
				go ibmxforcexchangeip(searchIPDomain, finflag)
				<-finflag
			}
			for index, ipInfo := range cymonIpResult.Hits {
				ipresult.Title = ipInfo.Title
				ipresult.Description = ipInfo.Description
				ipresult.ReportedBy = ipInfo.ReportedBy
				if len(ipInfo.Tags) > 0 {
					ipresult.Tag = ipInfo.Tags[0]
				}
				ipresult.URL = ipInfo.Ioc.URL
				ipresult.Hostname = ipInfo.Ioc.Hostname
				ipresult.IP = ipInfo.Ioc.IP
				ipresult.Country = ipInfo.Location.Country
				ipresult.City = ipInfo.Location.City
				ipresult.Domain = ipInfo.Ioc.Domain
				scanResultStructForTemplate.CymonIpInfo[string(index)] = ipresult
			}

			err = mmsatpl.Execute(httpwr, scanResultStructForTemplate)
			if err != nil {
				fmt.Println(err)
			}

		} else {
			//clear values
			for k := range scanResultStructForTemplate.Jottiscanres {
				delete(scanResultStructForTemplate.Jottiscanres, k)
			}

			//clear values
			for k := range scanResultStructForTemplate.AvCaesorAVFileInfoResult {
				delete(scanResultStructForTemplate.AvCaesorAVFileInfoResult, k)
			}

			//clear values
			for k := range scanResultStructForTemplate.AvCaesorAVEngineResult {
				delete(scanResultStructForTemplate.AvCaesorAVEngineResult, k)
			}

			//clear values
			for k := range scanResultStructForTemplate.MetaScanres {
				delete(scanResultStructForTemplate.MetaScanres, k)
			}

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
				//fmt.Println("Search val  is " + searchval)
				if err != nil {
					fmt.Println(err)
				}
				finflag := make(chan string)
				go jottiscanprocess(file, filename, finflag)
				go uploadfiletoavcaesar(filename, finflag)
				go metadefenderfilescan(filename, finflag)
				time.Sleep(6000 * time.Millisecond)
				//jottires, avcaesorres, metascanres :=
				<-finflag
				<-finflag
				<-finflag
				//fmt.Println(jottires + avcaesorres + metascanres)

				/*for k, v := range scanResultStructForTemplate.Jottiscanres{
					 fmt.Printf("%s\t\t%s\t\t%s\n ", k,v[0],v[1])
				 }*/

				//fmt.Printf("Data ID : %s", metascanDataId.DataID)
				metadefreserr := json.Unmarshal(getmetadefenderfilescanresult(metascanDataId.DataID), &metascanResult)
				if metadefreserr != nil {
					fmt.Println(metadefreserr)
				}
				metadefenderscanprocess()

				/*for k, v := range scanResultStructForTemplate.MetaScanres{
					 fmt.Printf("%s\t\t%s\t\t%s\n ", k,v[0],v[1])
				 }*/
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
