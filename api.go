package main

import (
	// "bytes"
	// "crypto/tls"
	// "crypto/x509"
	// "encoding/json"
	"flag"
	"strconv"

	//"io"
	"io/ioutil"

	"fmt"
	// "io"
	// "io/ioutil"
	"log"
	"net"
	"net/http"

	// "net/url"
	"os"
	// "strconv"
	// "strings"
	// "sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	// "github.com/go-ldap/ldap/v3"
	// _ "github.com/go-sql-driver/mysql"
	// ginprometheus "github.com/zsais/go-gin-prometheus"
	getenvs "gitlab.com/avarf/getenvs"
)

// Units.
// const (
// 	_        = iota
// 	KB int64 = 1 << (10 * iota)
// 	MB
// 	GB
// 	TB
// )

var (
	cert string
	key  string
	ca   string
	port string
	name string
)

func init() {
	flag.StringVar(&cert, "cert", "", "give me a certificate")
	flag.StringVar(&key, "key", "", "give me a key")
	flag.StringVar(&ca, "cacert", "", "give me a CA chain, enforces mutual TLS")
	flag.StringVar(&port, "port", getenvs.GetEnvString("WHOAMI_PORT", "8080"), "give me a port number")
	flag.StringVar(&name, "name", os.Getenv("WHOAMI_NAME"), "give me a name")
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

func main() {
	log.Println("------------------------ Start ------------------------")
	flag.Parse()

	// http.HandleFunc("/data", dataHandler)
	// http.HandleFunc("/echo", echoHandler)
	// http.HandleFunc("/bench", benchHandler)
	// http.HandleFunc("/", whoamiHandler)
	// http.HandleFunc("/api", apiHandler)
	// http.HandleFunc("/health", healthHandler)
	// http.HandleFunc("/ping", pingHandler)

	router := gin.Default()

	router.GET("/", whoamiHandler)
	// router.GET("/data", dataHandler)
	router.GET("/ping", pingHandler)
	router.GET("/echo", echoHandler)
	router.POST("/echo", echoHandler)

	//var w http.ResponseWriter = c.Writer
	//var req *http.Request = c.Req




	// router.POST("/somePost", posting)
	// router.PUT("/somePut", putting)
	// router.DELETE("/someDelete", deleting)
	// router.PATCH("/somePatch", patching)
	// router.HEAD("/someHead", head)
	// router.OPTIONS("/someOptions", options)

	// By default it serves on :8080 unless a
	// PORT environment variable was defined.

	router.Run(":"+port)


	// if len(cert) > 0 && len(key) > 0 {
	// 	server := &http.Server{
	// 		Addr: ":" + port,
	// 	}

	// 	if len(ca) > 0 {
	// 		server.TLSConfig = setupMutualTLS(ca)
	// 	}

	// 	log.Fatal(server.ListenAndServeTLS(cert, key))
	// }
	// log.Fatal(http.ListenAndServe(":"+port, nil))
}

// func setupMutualTLS(ca string) *tls.Config {
// 	clientCACert, err := ioutil.ReadFile(ca)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	clientCertPool := x509.NewCertPool()
// 	clientCertPool.AppendCertsFromPEM(clientCACert)

// 	tlsConfig := &tls.Config{
// 		ClientAuth:               tls.RequireAndVerifyClientCert,
// 		ClientCAs:                clientCertPool,
// 		PreferServerCipherSuites: true,
// 		MinVersion:               tls.VersionTLS12,
// 	}

// 	return tlsConfig
// }


func pingHandler(c *gin.Context) {

	pHostname := os.Getenv("HOSTNAME") //string
	pDate := time.Now().Unix()         //int64
	pMessage := "pong"                 //string

	if c.Query("format") != "json" {
		c.String(http.StatusOK, "Hostname: "+pHostname+"\nDate: "+strconv.FormatInt(pDate,10)+"\nMessage: "+pMessage)
	} else {
		var data struct {
			Hostname string     `json:"hostname,omitempty"`
			Date     int64  	`json:"date,omitempty"`
			Message	 string		`json:"message,omitempty"`
		}
		data.Hostname =	pHostname
		data.Date = pDate
		data.Message = pMessage
		c.JSON(http.StatusOK, data)
		// c.JSON(http.StatusOK, gin.H{
		// 	"hostname": 	os.Getenv("HOSTNAME"),
		// 	"date":  		time.Now().Unix(),
		// 	"url":      	c.Request.RequestURI,
		// 	"method":   	c.Request.Method,
		// 	"message":		"pong",
		// })		
	}
}


// func benchHandler(w http.ResponseWriter, _ *http.Request) {
// 	w.Header().Set("Connection", "keep-alive")
// 	w.Header().Set("Content-Type", "text/plain")
// 	_, _ = fmt.Fprint(w, "1")
// }

func echoHandler(c *gin.Context) {
	params := c.Request.URL.Query()
	log.Printf("[echo query] %s", params)

	if jsonData, err := ioutil.ReadAll(c.Request.Body); err == nil {
		log.Printf("[echo post] %s", string(jsonData))
	}

	c.String(http.StatusOK, "OK")
}

// 	for {
// 		messageType, p, err := conn.ReadMessage()
// 		if err != nil {
// 			return
// 		}

// 		printBinary(p)
// 		err = conn.WriteMessage(messageType, p)
// 		if err != nil {
// 			return
// 		}
// 	}
// }

// func printBinary(s []byte) {
// 	fmt.Printf("Received b:")
// 	for n := 0; n < len(s); n++ {
// 		fmt.Printf("%d,", s[n])
// 	}
// 	fmt.Printf("\n")
// }

// func dataHandler(w http.ResponseWriter, r *http.Request) {
// 	u, _ := url.Parse(r.URL.String())
// 	queryParams := u.Query()

// 	size, err := strconv.ParseInt(queryParams.Get("size"), 10, 64)
// 	if err != nil {
// 		size = 1
// 	}
// 	if size < 0 {
// 		size = 0
// 	}

// 	unit := queryParams.Get("unit")
// 	switch strings.ToLower(unit) {
// 	case "kb":
// 		size *= KB
// 	case "mb":
// 		size *= MB
// 	case "gb":
// 		size *= GB
// 	case "tb":
// 		size *= TB
// 	}

// 	attachment, err := strconv.ParseBool(queryParams.Get("attachment"))
// 	if err != nil {
// 		attachment = false
// 	}

// 	content := fillContent(size)

// 	if attachment {
// 		w.Header().Set("Content-Disposition", "Attachment")
// 		http.ServeContent(w, r, "data.txt", time.Now(), content)
// 		return
// 	}

// 	if _, err := io.Copy(w, content); err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// }

func whoamiHandler (c *gin.Context) {
	var w http.ResponseWriter = c.Writer
	var req *http.Request = c.Request
	wait := c.Query("wait")
	if len(wait) > 0 {
		duration, err := time.ParseDuration(wait)
		if err == nil {
			time.Sleep(duration)
		}
	}

	if name != "" {
		_, _ = fmt.Fprintln(w, "Name:", name)
	}

	hostname := os.Getenv("HOSTNAME")
	_, _ = fmt.Fprintln(w, "Hostname:", hostname)

	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		// handle err
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			_, _ = fmt.Fprintln(w, "IP:", ip)
		}
	}

	_, _ = fmt.Fprintln(w, "RemoteAddr:", req.RemoteAddr)
	if err := req.Write(w); err != nil {
		//http.Error(w, err.Error(), http.StatusInternalServerError)
		c.String(http.StatusInsufficientStorage, "Errors")
		log.Printf(err.Error())
		return
	}
}


// func apiHandler(w http.ResponseWriter, req *http.Request) {
// 	hostname, _ := os.Hostname()

// 	data := struct {
// 		Hostname string      `json:"hostname,omitempty"`
// 		IP       []string    `json:"ip,omitempty"`
// 		Headers  http.Header `json:"headers,omitempty"`
// 		URL      string      `json:"url,omitempty"`
// 		Host     string      `json:"host,omitempty"`
// 		Method   string      `json:"method,omitempty"`
// 		Name     string      `json:"name,omitempty"`
// 	}{
// 		Hostname: hostname,
// 		IP:       []string{},
// 		Headers:  req.Header,
// 		URL:      req.URL.RequestURI(),
// 		Host:     req.Host,
// 		Method:   req.Method,
// 		Name:     name,
// 	}

// 	ifaces, _ := net.Interfaces()
// 	for _, i := range ifaces {
// 		addrs, _ := i.Addrs()
// 		// handle err
// 		for _, addr := range addrs {
// 			var ip net.IP
// 			switch v := addr.(type) {
// 			case *net.IPNet:
// 				ip = v.IP
// 			case *net.IPAddr:
// 				ip = v.IP
// 			}
// 			if ip != nil {
// 				data.IP = append(data.IP, ip.String())
// 			}
// 		}
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	if err := json.NewEncoder(w).Encode(data); err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// }

// type healthState struct {
// 	StatusCode int
// }

// var (
// 	currentHealthState = healthState{http.StatusOK}
// 	mutexHealthState   = &sync.RWMutex{}
// )

// func healthHandler(w http.ResponseWriter, req *http.Request) {
// 	if req.Method == http.MethodPost {
// 		var statusCode int

// 		if err := json.NewDecoder(req.Body).Decode(&statusCode); err != nil {
// 			http.Error(w, err.Error(), http.StatusBadRequest)
// 			return
// 		}

// 		fmt.Printf("Update health check status code [%d]\n", statusCode)

// 		mutexHealthState.Lock()
// 		defer mutexHealthState.Unlock()
// 		currentHealthState.StatusCode = statusCode
// 	} else {
// 		mutexHealthState.RLock()
// 		defer mutexHealthState.RUnlock()
// 		w.WriteHeader(currentHealthState.StatusCode)
// 	}
// }

// func fillContent(length int64) io.ReadSeeker {
// 	charset := "-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
// 	b := make([]byte, length)

// 	for i := range b {
// 		b[i] = charset[i%len(charset)]
// 	}

// 	if length > 0 {
// 		b[0] = '|'
// 		b[length-1] = '|'
// 	}

// 	return bytes.NewReader(b)
// }

// func getEnv(key, fallback string) string {
// 	value := os.Getenv(key)
// 	if len(value) == 0 {
// 		return fallback
// 	}
// 	return value
// }
