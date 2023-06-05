package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	VERSION     = "v1.1"
	config_file = "config.json"
	data_path   = "data"
	aes_key     = "my pass phrase"
)

var port = 8080

// go:embed public
var contentStatic embed.FS

var broker *Broker

func main() {
	_, err := os.Stat(data_path)
	if os.IsNotExist(err) {
		err := os.Mkdir(data_path, os.ModePerm)
		if err != nil {
			log.Fatalf("Cannot create data directory:%v", err)
		}
	}

	// Make a new Broker instance
	broker = &Broker{
		make(map[chan string]bool),
		make(chan (chan string)),
		make(chan (chan string)),
		make(chan string),
	}

	// Start processing events
	broker.Start()

	// Make b the HTTP handler for "/events/".  It can do
	// this because it has a ServeHTTP method.  That method
	// is called in a separate goroutine for each
	// request to "/events/".
	http.Handle("/events/", broker)

	mutex := http.NewServeMux()
	mutex.Handle("/local_server_sse", broker)
	mutex.HandleFunc("/writeData", writeData)
	mutex.HandleFunc("/getData", getData)
	mutex.HandleFunc("/sendMessage", sendMessage)
	fileServer := http.FileServer(http.Dir("./public"))
	mutex.Handle("/", wrapHandler(fileServer))

	go startUp()
	go func() {
		for {
			time.Sleep(2 * time.Second)
		}
	}()

	fmt.Printf("Starting server at port %d\n", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), mutex))
}

func startUp() {
	_, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		log.Fatal(err)
	}

	// The browser can connect now because the listening socket is open.

	err = exec.Command("cmd", "/C", "start", fmt.Sprintf("http://localhost:%d", port)).Start()
	if err != nil {
		log.Println(err)
	}

}

// structs
type NotFoundRedirectRespWr struct {
	http.ResponseWriter // We embed http.ResponseWriter
	status              int
}

type File struct {
	Name string `json:"name"`
	Data string `json:"data"`
}

//helper functions
func (w *NotFoundRedirectRespWr) WriteHeader(status int) {
	w.status = status // Store the status for our own use
	if status != http.StatusNotFound {
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *NotFoundRedirectRespWr) Write(p []byte) (int, error) {
	if w.status != http.StatusNotFound {
		return w.ResponseWriter.Write(p)
	}
	return len(p), nil // Lie that we successfully written it
}

func setResponseCookie(w http.ResponseWriter, name string, value string) {
	cookie := &http.Cookie{
		Name:   name,
		Value:  value,
		MaxAge: 300,
		Path:   "/",
	}
	http.SetCookie(w, cookie)
}

func wrapHandler(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/" && !strings.Contains(r.RequestURI, ".") {
			setResponseCookie(w, "origin_request", r.RequestURI)
		}
		nfrw := &NotFoundRedirectRespWr{ResponseWriter: w}
		// r.URL.Path = fmt.Sprintf("/public%s", r.URL.Path)
		h.ServeHTTP(nfrw, r)
		if nfrw.status == 404 {
			log.Printf("Redirecting %s to index.html.", r.RequestURI)
			http.Redirect(w, r, "/index.html", http.StatusFound)
		}
	}
}

func listFiles(dir string, pattern string) []string{
	files, err := ioutil.ReadDir(dir)
    if err != nil {
        log.Fatal(err)
    }

	var list []string
    for _, f := range files {
		if len(pattern) == 0 || strings.Contains(f.Name(), pattern) {
        	list = append(list, f.Name())
		}
    }
	return list
}

func setCors(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	w.Header().Add("Connection", "keep-alive")
	w.Header().Add("Access-Control-Allow-Origin", origin)
	w.Header().Add("Vary", "Origin")
	w.Header().Add("Access-Control-Allow-Credentials", "true")
	w.Header().Add("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Add("Access-Control-Allow-Headers", "access-control-allow-headers,content-type,crossdomain,gih_session")
	w.Header().Add("Content-Type", "application/json; charset=UTF-8")
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return false
	}
	return true
}

func getFormBody(r *http.Request, w http.ResponseWriter, status []byte) []byte {
	if err := r.ParseForm(); err != nil {
		log.Fatalf("ParseForm() err: %v", err)
		w.Write(status)
		return nil
	}

	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("read body error: %v", err)
		w.Write(status)
		return nil
	}
	return b
}

func getFilePath(path string, name string) string {
	return fmt.Sprintf("%s/%s", path, name)
}

func encryptAES(text []byte) []byte {
	// generate a new aes cipher using our 32 byte long key
	c, err := aes.NewCipher([]byte(aes_key))
	// if there are any errors, handle them
	if err != nil {
		fmt.Println(err)
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	// if any error generating new GCM
	// handle them
	if err != nil {
		fmt.Println(err)
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}

	// here we encrypt our text using the Seal function
	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	return gcm.Seal(nonce, nonce, text, nil)
}

func decryptAES(ciphertext []byte) []byte {
	c, err := aes.NewCipher([]byte(aes_key))
	if err != nil {
		fmt.Println(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		fmt.Println(err)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	return plaintext
}

func writeLocalData(path string, data []byte) bool {
	file, err := os.Create(path)
	if err != nil {
		log.Fatalln(err)
		return false
	}
	ciphertext := encryptAES([]byte(data))
	_, err = file.Write(ciphertext)
	return err == nil
}

func readLocalData(path string) []byte {
	data, err := ioutil.ReadFile(path)
	if err == nil {
		return decryptAES(data)
	}
	return nil
}

// handlers
func getData(w http.ResponseWriter, r *http.Request) {
	if !setCors(w, r) {
		return
	}
	body := getFormBody(r, w, []byte("error reading getData form"))
	if body == nil {
		return
	}
	file := &File{}
	err := json.Unmarshal(body, file)
	if err == nil {
		data := readLocalData(getFilePath(data_path, file.Name))
		if data != nil {
			w.Write(data)
		}
	} else {
		w.Write([]byte("error reading local file"))
	}
}

func writeData(w http.ResponseWriter, r *http.Request) {
	if !setCors(w, r) {
		return
	}
	body := getFormBody(r, w, []byte("error reading writeData form"))
	if body == nil {
		return
	}
	file := &File{}
	err := json.Unmarshal(body, file)
	if err == nil {
		writeLocalData(getFilePath(data_path, file.Name), []byte(file.Data))
		w.Write([]byte(""))
	} else {
		w.Write([]byte("error writing local file"))
	}

}

// A single Broker will be created in this program. It is responsible
// for keeping a list of which clients (browsers) are currently attached
// and broadcasting events (messages) to those clients.
type Broker struct {

	// Create a map of clients, the keys of the map are the channels
	// over which we can push messages to attached clients.  (The values
	// are just booleans and are meaningless.)
	//
	clients map[chan string]bool

	// Channel into which new clients can be pushed
	//
	newClients chan chan string

	// Channel into which disconnected clients should be pushed
	//
	defunctClients chan chan string

	// Channel into which messages are pushed to be broadcast out
	// to attahed clients.
	//
	messages chan string
}

// This Broker method starts a new goroutine.  It handles
// the addition & removal of clients, as well as the broadcasting
// of messages out to clients that are currently attached.
func (b *Broker) Start() {

	// Start a goroutine
	//
	go func() {

		// Loop endlessly
		//
		for {

			// Block until we receive from one of the
			// three following channels.
			select {

			case s := <-b.newClients:

				// There is a new client attached and we
				// want to start sending them messages.
				b.clients[s] = true
				log.Printf("Added new client: %d\n", len(b.clients))

			case s := <-b.defunctClients:

				// A client has dettached and we want to
				// stop sending them messages.
				delete(b.clients, s)
				close(s)

				log.Printf("Removed client: %d\n", len(b.clients))

			case msg := <-b.messages:

				// There is a new message to send.  For each
				// attached client, push the new message
				// into the client's message channel.
				for s := range b.clients {
					s <- msg
				}
				log.Printf("Broadcast message to %d clients", len(b.clients))
			}
		}
	}()
}

// This Broker method handles and HTTP request at the "/events/" URL.
var exists = struct{}{}

type clientSet struct {
    m map[string]struct{}
}

func NewSet() *clientSet {
    s := &clientSet{}
    s.m = make(map[string]struct{})
    return s
}

func (s *clientSet) Add(value string) {
    s.m[value] = exists
}

func (s *clientSet) Remove(value string) {
    delete(s.m, value)
}

func (s *clientSet) Contains(value string) bool {
    _, c := s.m[value]
    return c
}

var clients = NewSet()
func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !setCors(w, r) {
		return
	}
	// Make sure that the writer supports flushing.
	//
	f, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	// Create a new channel, over which the broker can
	// send this client messages.
	if clients.Contains(r.RequestURI) {
		return
	}
	clients.Add(r.RequestURI)
	log.Printf("Openning %s\n", r.RequestURI);
	messageChan := make(chan string)

	// Add this client to the map of those that should
	// receive updates
	b.newClients <- messageChan

	// Listen to the closing of the http connection via the CloseNotifier
	notify := w.(http.CloseNotifier).CloseNotify()
	go func() {
		<-notify
		// Remove this client from the map of attached clients
		// when `EventHandler` exits.
		b.defunctClients <- messageChan
		log.Println("HTTP connection just closed.")
	}()

	// Set the headers related to event streaming.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Transfer-Encoding", "chunked")

	// Don't close the connection, instead loop endlessly.
	for {

		// Read from our messageChan.
		msg, open := <-messageChan

		if !open {
			// If our messageChan was closed, this means that the client has
			// disconnected.
			log.Printf("Closing %s\n", r.RequestURI)
			clients.Remove(r.RequestURI)
			break
		}

		// Write to the ResponseWriter, `w`.
		fmt.Fprintf(w, "data: %s\n\n", msg)

		// Flush the response.  This is only possible if
		// the repsonse supports streaming.
		f.Flush()
	}

	// Done.
	log.Println("Finished HTTP request at ", r.URL.Path)
}

func sendMessage(w http.ResponseWriter, r *http.Request)  {
	if !setCors(w, r) {
		return
	}
	message := getFormBody(r, w, []byte("sendMessage: failed to parse body"))
	broker.messages <- string(message)
	w.WriteHeader(http.StatusNoContent)
}
