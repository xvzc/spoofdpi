package proto

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// validMethods contains the set of HTTP methods that are considered valid
var validMethods = map[string]bool{
	"DELETE":      true,
	"GET":         true,
	"HEAD":        true,
	"POST":        true,
	"PUT":         true,
	"CONNECT":     true,
	"OPTIONS":     true,
	"TRACE":       true,
	"COPY":        true,
	"LOCK":        true,
	"MKCOL":       true,
	"MOVE":        true,
	"PROPFIND":    true,
	"PROPPATCH":   true,
	"SEARCH":      true,
	"UNLOCK":      true,
	"BIND":        true,
	"REBIND":      true,
	"UNBIND":      true,
	"ACL":         true,
	"REPORT":      true,
	"MKACTIVITY":  true,
	"CHECKOUT":    true,
	"MERGE":       true,
	"M-SEARCH":    true,
	"NOTIFY":      true,
	"SUBSCRIBE":   true,
	"UNSUBSCRIBE": true,
	"PATCH":       true,
	"PURGE":       true,
	"MKCALENDAR":  true,
	"LINK":        true,
	"UNLINK":      true,
}

// HTTPRequest wraps the standard http.Request with additional functionality
type HTTPRequest struct {
	*http.Request
}

// NewHttpRequest creates a new HttpRequest from an http.Request
func NewHttpRequest(req *http.Request) *HTTPRequest {
	return &HTTPRequest{Request: req}
}

// readHttpRequest reads and parses an HTTP request from the given reader
func ReadHttpRequest(rdr io.Reader) (*HTTPRequest, error) {
	req, err := http.ReadRequest(bufio.NewReader(rdr))
	if err != nil {
		if err == io.EOF {
			return nil, err
		}

		return nil, err
	}
	return NewHttpRequest(req), nil
}

// ExtractHost returns the host without port information
func (r *HTTPRequest) ExtractHost() string {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		return r.Host
	}
	return host
}

// ExtractPort returns the port from the host or empty string if not specified
func (r *HTTPRequest) ExtractPort() (int, error) {
	_, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		if r.Method == http.MethodConnect {
			return 443, nil
		} else {
			return 80, nil
		}
	}

	return strconv.Atoi(port)
}

// IsValidMethod returns true if the request method is a valid HTTP method
func (r *HTTPRequest) IsValidMethod() bool {
	return validMethods[r.Method]
}

// IsConnectMethod returns true if the request method is CONNECT
func (r *HTTPRequest) IsConnectMethod() bool {
	return r.Method == http.MethodConnect
}

// IsUpgrade reports whether the request asks to switch the connection to
// another protocol, such as WebSocket.
func (r *HTTPRequest) IsUpgrade() bool {
	return httpguts.HeaderValuesContainsToken(r.Header["Connection"], "upgrade")
}

// SetConnectionClose makes the request the last one on the connection it is
// written to. It drops the hop-by-hop headers that describe the client's own
// connection (Connection, the headers it names, Keep-Alive and
// Proxy-Connection), so that writing the request sends "Connection: close"
// as its only connection option.
func (r *HTTPRequest) SetConnectionClose() {
	for _, v := range r.Header["Connection"] {
		for name := range strings.SplitSeq(v, ",") {
			if name = textproto.TrimString(name); name != "" {
				r.Header.Del(name)
			}
		}
	}
	r.Header.Del("Connection")
	r.Header.Del("Keep-Alive")
	r.Header.Del("Proxy-Connection")
	r.Close = true
}

type HTTPResponse struct {
	*http.Response
}

func NewHTTPResponse(proto string, code int) *HTTPResponse {
	res := &http.Response{Proto: proto, StatusCode: code}
	return &HTTPResponse{Response: res}
}

func HTTPBadGatewayResponse() *HTTPResponse {
	return &HTTPResponse{
		&http.Response{
			ProtoMajor: 1,
			ProtoMinor: 1,
			StatusCode: 502,
			Status:     "502 Bad Gateway",
		},
	}
}

func HTTPConnectionEstablishedResponse() *HTTPResponse {
	return &HTTPResponse{
		&http.Response{
			ProtoMajor: 1,
			ProtoMinor: 1,
			StatusCode: 200,
			Status:     "200 Connection Established",
		},
	}
}

func HTTPForbiddenResponse() *HTTPResponse {
	return &HTTPResponse{
		&http.Response{
			ProtoMajor: 1,
			ProtoMinor: 1,
			StatusCode: 403,
			Status:     "403 Forbidden",
		},
	}
}

func HTTPBadRequestResponse() *HTTPResponse {
	return &HTTPResponse{
		&http.Response{
			ProtoMajor: 1,
			ProtoMinor: 1,
			StatusCode: 400,
			Status:     "400 Bad Request",
		},
	}
}

func HTTPNotImplementedResponse() *HTTPResponse {
	return &HTTPResponse{
		&http.Response{
			ProtoMajor: 1,
			ProtoMinor: 1,
			StatusCode: 501,
			Status:     "501 Not Implemented",
		},
	}
}

//
// func (r *HTTPRequest) ConnEstablishedResponse() []byte {
// 	return []byte(r.Proto + " \r\n\r\n")
// }
