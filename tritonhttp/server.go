package tritonhttp

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Server struct {
	// Addr specifies the TCP address for the server to listen on,
	// in the form "host:port". It shall be passed to net.Listen()
	// during ListenAndServe().
	Addr string // e.g. ":0"

	// VirtualHosts contains a mapping from host name to the docRoot path
	// (i.e. the path to the directory to serve static files from) for
	// all virtual hosts that this server supports
	VirtualHosts map[string]string
}

func (s *Server) ValidateVirtualHosts() error {
	for hostName, dir := range s.VirtualHosts {
		log.Printf("Validating host %v at %v\n", hostName, dir)
		fi, err := os.Stat(dir)
		if os.IsNotExist(err) {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("docroot %v is not a directory", dir)
		}
	}
	return nil
}

// ListenAndServe listens on the TCP network address s.Addr and then
// handles requests on incoming connections.
func (s *Server) ListenAndServe() error {

	// Hint: Validate all docRoots
	// Validate the configuration of the server
	if err := s.ValidateVirtualHosts(); err != nil {
		return err
	}

	// Hint: create your listen socket and spawn off goroutines per incoming client
	listener, err := net.Listen("tcp", s.Addr)
	if err != nil {
		log.Panicf("Listen error raised - %s\n", err)
		return err
	}
	log.Printf("Listening to connections at '%v'\n", s.Addr)
	defer listener.Close()

	// Accept connections forever
	for {
		conn, err := listener.Accept()
		if err != nil {
			// log.Printf("server %v accept has error - %s\n", s.Addr, err)
			continue
		}
		go s.HandleRequest(conn)
	}

}

// Start reading & processing request
func (s *Server) HandleRequest(conn net.Conn) {

	br := bufio.NewReader(conn)

	// Read the response from the connection
	for {

		// Set a read timeout
		if err := conn.SetReadDeadline(time.Now().Add(RECV_TIMEOUT)); err != nil {
			log.Printf("Error raised when setting read timeout.\n")
			conn.Close()
			return
		}

		// Read (next) request from the client (connection)
		req, err := ReadRequest(br)

		// Handle errors
		// Error 1: The client has closed the connection - io.EOF
		if err == io.EOF {
			log.Printf("Client %v has closed the connection\n", conn.RemoteAddr())
			conn.Close()
			return
		}

		// Error 2: Timeout from the server - net.Error
		// Timeout in this application means we just close the connection
		// Note: proj3 reqruie you do do a bit more here
		// => Return 400 Bad Request response
		if err, ok := err.(net.Error); ok && err.Timeout() {
			log.Printf("Timeout from the server - net.Error")
			// Send 400 Bad Request response
			res := PrepareResponse()
			res.HandleBadRequest()
			err2 := res.Write(conn)
			if err2 != nil {
				log.Printf("Send 400 request for timeout from server failed - %v", err)
			}
			conn.Close()
			return
		}

		// Error 3: Maformed/invalid request
		// => Return 400 Bad Request response
		if err != nil {
			log.Printf("Error raised when reading request - %v\n", err)
			// Send 400 Bad Request response
			res := PrepareResponse()
			res.HandleBadRequest()
			err2 := res.Write(conn)
			if err2 != nil {
				log.Printf("Send 400 request for unsuccessful reading failed - %v", err)
			}
			conn.Close()
			return
		}

		// "Error" 4: Connection: close
		if req.Close {
			log.Printf("Received closing request from client %v\n", conn.RemoteAddr())
			log.Printf("Closing connection with client %v\n", conn.RemoteAddr())
			// Send 400 Bad Request response
			res := PrepareResponse()
			res.HandleBadRequest()
			err2 := res.Write(conn)
			if err2 != nil {
				log.Printf("Send 400 request for empty host failed - %v", err)
			}
			conn.Close()
			return
		}

		// Error 5: Empty Host in header
		if req.Host == "" {
			log.Printf("Error raised for empty host\n")
			// Send 400 Bad Request response
			res := PrepareResponse()
			res.HandleBadRequest()
			err2 := res.Write(conn)
			if err2 != nil {
				log.Printf("Send 400 request for empty host failed - %v", err)
			}
			conn.Close()
			return
		}

		// Handle good request
		log.Printf("Handling good request\n")

		// Start checking if URL/host is valid
		// Check if given host exists
		root, ok := s.VirtualHosts[req.Host]
		var targetFile string
		if ok {
			targetFile = filepath.Join(root, req.URL)
		} else {
			log.Printf("Error raised for invalid host - \"%v\"\n", req.Host)
			// Send 404 Not Found response
			res := PrepareResponse()
			res.HandleNotFound()
			err2 := res.Write(conn)
			if err2 != nil {
				log.Printf("Send 404 request for invalid host failed - %v", err)
			}
			continue
		}

		// Check if url exists/has error
		targetFile = filepath.Clean(targetFile)
		targetFileInfo, err := os.Stat(targetFile)
		if os.IsNotExist(err) {
			log.Printf("File does not exist - \"%v\"", req.URL)
			// Send 404 Not Found response
			res := PrepareResponse()
			res.HandleNotFound()
			err2 := res.Write(conn)
			if err2 != nil {
				log.Printf("Send 404 request for file path failed - %v", err)
			}
			continue
		}
		if err != nil {
			log.Printf("Failed loading file - \"%v\"", req.URL)
			// Send 404 Not Found response
			res := PrepareResponse()
			res.HandleNotFound()
			err2 := res.Write(conn)
			if err2 != nil {
				log.Printf("Send 404 request for loading file failed - %v", err)
			}
			continue
		}

		// Append index.html if needed and check if url is valid for new path
		if targetFileInfo.IsDir() {
			targetFile += "index.html"
			targetFileInfo, err = os.Stat(targetFile)
			if os.IsNotExist(err) {
				log.Printf("File does not exist - \"%v\"", req.URL)
				// Send 404 Not Found response
				res := PrepareResponse()
				res.HandleNotFound()
				err2 := res.Write(conn)
				if err2 != nil {
					log.Printf("Send 404 request for file path failed - %v", err)
				}
				continue
			}
		}

		// Check if url is in authorized direction
		if strings.HasPrefix(targetFile, root) {
			// Send 200 Ok response
			res := PrepareResponse()
			res.HandleOk()
			err2 := res.SetHeadersAndBody(targetFile, targetFileInfo)
			if err2 != nil {
				log.Printf("Error occured when accessing file - \"%v\"", req.URL)
			}
			err2 = res.Write(conn)
			if err2 != nil {
				log.Printf("Send 404 request for unauthorized access failed - %v", err)
			}
			continue
		} else {
			log.Printf("File access is not authorized - \"%v\"", req.URL)
			// Send 404 Not Found response
			res := PrepareResponse()
			res.HandleNotFound()
			err2 := res.Write(conn)
			if err2 != nil {
				log.Printf("Send 404 request for unauthorized access failed - %v", err)
			}
			continue
		}

		// We'll never close the connection and handle as many requests for this connection
		// and pass on this responsibility to the timeout mechanism
	}

}

// Read and parse the request
func ReadRequest(br *bufio.Reader) (req *Request, err error) {
	req = &Request{}
	req.init()

	// Read start line
	line, err := ReadLine(br)
	if err != nil {
		return nil, err
	}

	// Process the request
	// fmt.Println("Here 2!!!!!")
	req.Method, req.URL, req.Proto, err = ParseRequestLine(line)
	if err != nil {
		return nil, err
	}

	// Validate method
	if !ValidateRequestMethod(req.Method) {
		return nil, fmt.Errorf("invalid method, expected \"GET\", received \"%v\"", req.Method)
	}

	// Validate protocol version
	if !ValidateProtoVersion(req.Proto) {
		return nil, fmt.Errorf("invalid protocol version, expected \"GET\", received \"%v\"", req.Proto)
	}

	// Validate URL
	if !ValidateURL(req.URL) {
		return nil, fmt.Errorf("invalid URL, expected start with \"/\", received \"%v\"", req.URL)
	}

	// Start reading the header
	hasHost := false
	for {
		line, err := ReadLine(br)
		if err != nil {
			return nil, err
		}
		// End of header
		if line == "" {
			break
		}

		// Processing the header content
		header := strings.SplitN(line, ":", 2)
		if len(header) != 2 {
			return nil, fmt.Errorf("incorrect header format for, expected <key><colon>(<space>*)<value><CRLF>, received %v", line)
		}

		// Parse key-value
		key := strings.TrimSpace(header[0])
		_, err = ValidateHeaderKey(key)
		if err != nil {
			return nil, err
		}
		key = CanonicalHeaderKey(key)
		val := strings.TrimSpace(header[1])

		// Process header
		if key == "Host" {
			hasHost = true
			req.Host = val
		} else if key == "Connection" && val == "close" {
			req.Close = true
		} else {
			req.Headers[key] = val
		}
	}

	if !hasHost {
		return nil, fmt.Errorf("invalid header, missing \"Host\" in header")
	}

	return req, nil
}

// Parse the intial request line
func ParseRequestLine(line string) (string, string, string, error) {

	fields := strings.SplitN(line, " ", 3)
	if len(fields) != 3 {
		return "", "", "", fmt.Errorf("could not parse the request line - received\"%v\"", line)
	}

	return fields[0], fields[1], fields[2], nil
}

// Validate request method (if is "GET")
func ValidateRequestMethod(method string) bool {
	return method == "GET"
}

// Validate request method (if is "HTTP/1.1")
func ValidateProtoVersion(ver string) bool {
	return ver == ProtoVersion
}

// Validate request method (if starts with "/")
func ValidateURL(url string) bool {
	return strings.HasPrefix(url, "/")
}

// Key shoudl be trimmed before passing in
func ValidateHeaderKey(key string) (bool, error) {
	if strings.Contains(key, " ") {
		return false, fmt.Errorf("invalid header key - contains space in key: \"%v\"", key)
	}
	return true, nil
}

// Prepare a new response struct
func PrepareResponse() *Response {
	res := &Response{}
	res.init()
	return res
}

// ReadLine reads a single line ending with "\r\n" from br,
// striping the "\r\n" line end from the returned string.
// If any error occurs, data read before the error is also returned.
// You might find this function useful in parsing requests.
func ReadLine(br *bufio.Reader) (string, error) {
	var line string
	for {
		s, err := br.ReadString('\n')
		line += s
		// Return the error
		if err != nil {
			return line, err
		}
		// Return the line when reaching line end
		if strings.HasSuffix(line, "\r\n") {
			// Striping the line end
			line = line[:len(line)-2]
			return line, nil
		}
	}
}
