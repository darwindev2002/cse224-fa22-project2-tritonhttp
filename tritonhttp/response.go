package tritonhttp

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"strconv"
)

type Response struct {
	Proto      string // e.g. "HTTP/1.1"
	StatusCode int    // e.g. 200
	StatusText string // e.g. "OK"

	// Headers stores all headers to write to the response.
	Headers map[string]string

	// Request is the valid request that leads to this response.
	// It could be nil for responses not resulting from a valid request.
	// Hint: you might need this to handle the "Connection: Close" requirement
	Request *Request

	// FilePath is the local path to the file to serve.
	// It could be "", which means there is no file to serve.
	FilePath string

	// Optional body after header
	Body []byte
}

const (
	// Response statuses
	StatusOK         = 200
	StatusBadRequest = 400
	StatusNotFound   = 404
	// Protocol version
	ProtoVersion = "HTTP/1.1"
	// Sample 200 Response Body
	SampleResponseBody = `<html><body><h1>Hello, World!</h1></body></html>`
)

var statusText = map[int]string{
	StatusOK:         "OK",
	StatusBadRequest: "Bad Request",
	StatusNotFound:   "Not Found",
}

// Initialize response
func (res *Response) init() {
	res.Headers = make(map[string]string)
	// res.FilePath = "hello-world.txt"
	// r.FilePath = filepath.Join(s.DocRoot, "hello-world.txt")
}

// HandleBadRequest prepares res to be a 200 Ok
// When the request was successful
func (res *Response) HandleOk() {
	res.Proto = ProtoVersion
	res.StatusCode = StatusOK
}

// HandleBadRequest prepares res to be a 400 Bad Request
// When the client sent a malformed or invalid request
// that the server doesn’t understand
func (res *Response) HandlBadRequest() {
	res.Proto = ProtoVersion
	res.StatusCode = StatusBadRequest
	res.FilePath = ""
	res.Headers["Connection"] = "close"
}

// HandleBadRequest prepares res to be a 404 Not Found
// When the requested content wasn’t there
func (res *Response) HandlNotFound() {
	res.Proto = ProtoVersion
	res.StatusCode = StatusNotFound
	res.FilePath = ""
}

func (res *Response) CreateHeaders() {

	// Date

	// Last-Modified

	// Content-Type
	res.Headers["Content-Type"] = MIMETypeByExtension(path.Ext(res.FilePath))

	// Content-Length

	// Connection
	if res.StatusCode == StatusBadRequest {
		res.Headers["Connection"] = "close"
	}
}

func (res *Response) SetBody(body string) {
	res.Body = []byte(body)
	res.Headers["Content-Length"] = strconv.Itoa(len(res.Body))
}

func (res *Response) Write(w io.Writer) error {
	bw := bufio.NewWriter(w)

	// Writing initial response line (e.g. "HTTP/1.1 200 OK\r\n")
	statusLine := fmt.Sprintf("%v %v %v\r\n", res.Proto, res.StatusCode, statusText[res.StatusCode])
	if _, err := bw.WriteString(statusLine); err != nil {
		return err
	}

	// Writing response headers (e.g. "Connection: close\r\n")
	for key, val := range res.Headers {
		headerLine := fmt.Sprintf("%v: %v\r\n", key, val)
		if _, err := bw.WriteString(headerLine); err != nil {
			return err
		}
	}

	// Ending response header ("\r\n")
	if _, err := bw.WriteString("\r\n"); err != nil {
		return err
	}

	// Optional Body
	if res.StatusCode == StatusOK {
		if _, err := bw.Write(res.Body); err != nil {
			return err
		}
	}

	if err := bw.Flush(); err != nil {
		return err
	}

	return nil
}
