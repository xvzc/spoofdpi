package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"
)

// outcomeKind is how a server, or the DPI in front of it, answered an
// attempt.
type outcomeKind int

const (
	// outPass: the server answered with a ServerHello; the attempt got
	// through.
	outPass outcomeKind = iota
	// outRST: the connection was reset.
	outRST
	// outDrop: nothing came back before the wait ended.
	outDrop
	// outOther: any other answer; detail says which.
	outOther
	// outLocal: the attempt failed on this host, such as when the
	// ClientHello could not be built or the TTL could not be set; detail
	// says why. It says nothing about the DPI.
	outLocal
)

// outcome is the result of one attempt.
type outcome struct {
	kind   outcomeKind
	detail string
	// serverReplied is set when the server answered with TLS, such as an
	// alert, which a DPI does not inject.
	serverReplied bool
	// connectFailed is set when the connection itself failed, for a
	// reason other than a local error.
	connectFailed bool
	// answeredFake is set when the server answered the fake ClientHello
	// of the attempt with a ServerHello.
	answeredFake bool
	// rtt is the time the connection took to complete.
	rtt time.Duration
}

// localOutcome is the outcome of an attempt that failed on this host for
// reason.
func localOutcome(reason string) outcome {
	return outcome{kind: outLocal, detail: reason}
}

// residualClass is the class of the outcome of a benign ClientHello that
// residual checks compare: a ServerHello and a TLS alert are both the
// server answering.
func (o outcome) residualClass() string {
	switch {
	case o.kind == outPass, o.serverReplied:
		return "answered"
	case o.kind == outRST:
		return "RST"
	case o.kind == outDrop:
		return "silent"
	}
	return o.detail
}

// TLS record types and the handshake type of a ServerHello.
const (
	tlsRecordHandshake  = 0x16
	tlsRecordAlert      = 0x15
	tlsServerHelloType  = 0x02
	tlsRecordHeaderLen  = 5
	tlsAlertRecordBytes = 7
	// helloFixedLen is the length of a ServerHello from its handshake
	// length to its session ID length: handshake length 3, version 2,
	// random 32 and session ID length 1.
	helloFixedLen = 38
)

// helloCheck is what tells which ClientHello of an attempt that sent a
// fake one a ServerHello answers.
type helloCheck struct {
	// real and fake are the session IDs of the real and the fake
	// ClientHello. A TLS 1.3 server echoes the one it answers.
	real, fake []byte
	// linger is how long to keep reading after a ServerHello that echoes
	// neither, but not past deadline, the attempt's own.
	linger   time.Duration
	deadline time.Time
}

// readOutcome reads the server's answer on conn, until the deadline set on
// it: a ServerHello, including a HelloRetryRequest, passes.
func readOutcome(conn net.Conn) outcome {
	return readHello(context.Background(), conn, nil)
}

// readHello is readOutcome for an attempt that sent a fake ClientHello,
// as check describes. A ServerHello that echoes the real session ID
// passes, and one that echoes the fake one answered the fake. One that
// echoes neither, as a TLS 1.2 server does, passes unless an alert, a
// reset or a close follows within the linger: a server that took the fake
// ClientHello rejects the real one that follows it. The linger ends when
// ctx does.
func readHello(ctx context.Context, conn net.Conn, check *helloCheck) outcome {
	var buf [tlsAlertRecordBytes - 1]byte
	n, err := io.ReadFull(conn, buf[:])
	got := buf[:n]
	switch {
	case n == len(buf) && got[0] == tlsRecordHandshake && got[5] == tlsServerHelloType:
		if check == nil {
			return outcome{kind: outPass}
		}
		recordLen := int(binary.BigEndian.Uint16(got[3:tlsRecordHeaderLen]))
		return readServerHello(ctx, conn, recordLen, check)
	case n > 0 && got[0] == tlsRecordAlert:
		return alertOutcome(conn, n == len(buf))
	case n > 0:
		return outcome{kind: outOther, detail: "unexpected reply"}
	}
	return errOutcome(err)
}

// alertOutcome reads the description of an alert whose record has been
// read up to it, if whole.
func alertOutcome(conn net.Conn, whole bool) outcome {
	o := outcome{kind: outOther, detail: "TLS alert", serverReplied: true}
	if !whole {
		return o
	}
	var desc [1]byte
	if _, err := io.ReadFull(conn, desc[:]); err == nil {
		o.detail = fmt.Sprintf("TLS alert %d", desc[0])
	}
	return o
}

// readServerHello reads the session ID of a ServerHello of recordLen
// bytes whose record has been read up to its handshake type.
func readServerHello(
	ctx context.Context,
	conn net.Conn,
	recordLen int,
	check *helloCheck,
) outcome {
	var fixed [helloFixedLen]byte
	if _, err := io.ReadFull(conn, fixed[:]); err != nil {
		return afterHelloOutcome(err)
	}
	sid := make([]byte, fixed[helloFixedLen-1])
	if _, err := io.ReadFull(conn, sid); err != nil {
		return afterHelloOutcome(err)
	}
	switch {
	case bytes.Equal(sid, check.real):
		return outcome{kind: outPass}
	case bytes.Equal(sid, check.fake):
		return outcome{
			kind: outOther, detail: "answered fake", serverReplied: true, answeredFake: true,
		}
	}
	read := 1 + helloFixedLen + len(sid)
	return lingerAfterHello(ctx, conn, recordLen-read, check)
}

// lingerAfterHello skips the rest of a ServerHello record, skip bytes,
// and the records after it, for up to check.linger, until an alert or an
// error.
func lingerAfterHello(
	ctx context.Context,
	conn net.Conn,
	skip int,
	check *helloCheck,
) outcome {
	until := time.Now().Add(check.linger)
	if !check.deadline.IsZero() && check.deadline.Before(until) {
		until = check.deadline
	}
	_ = conn.SetReadDeadline(until)
	// A ctx that ended before the deadline was set had its past deadline
	// overwritten; one that ends later moves it to the past again.
	if ctx.Err() != nil {
		_ = conn.SetReadDeadline(time.Unix(1, 0))
	}
	if _, err := io.CopyN(io.Discard, conn, int64(max(skip, 0))); err != nil {
		return afterHelloOutcome(err)
	}
	for {
		var header [tlsRecordHeaderLen]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return afterHelloOutcome(err)
		}
		if header[0] == tlsRecordAlert {
			var level [1]byte
			_, err := io.ReadFull(conn, level[:])
			return alertOutcome(conn, err == nil)
		}
		length := int64(binary.BigEndian.Uint16(header[3:]))
		if _, err := io.CopyN(io.Discard, conn, length); err != nil {
			return afterHelloOutcome(err)
		}
	}
}

// afterHelloOutcome returns the outcome of a read after a ServerHello that
// failed with err. A timeout is the server waiting for the client's next
// message, which passes.
func afterHelloOutcome(err error) outcome {
	o := errOutcome(err)
	if o.kind == outDrop {
		return outcome{kind: outPass}
	}
	return o
}

// errOutcome returns the outcome of an attempt that failed with err, on
// connecting, writing or reading.
func errOutcome(err error) outcome {
	var netErr net.Error
	var errno syscall.Errno
	if errno, ok := localError(err); ok {
		return localOutcome("local error " + localErrorName(errno.Error()))
	}
	switch {
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ECONNREFUSED),
		errors.Is(err, syscall.EPIPE):
		return outcome{kind: outRST}
	case errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &netErr) && netErr.Timeout():
		return outcome{kind: outDrop}
	case errors.Is(err, io.EOF):
		return outcome{kind: outOther, detail: "closed"}
	case errors.As(err, &errno):
		return outcome{kind: outOther, detail: errno.Error()}
	}
	return outcome{kind: outOther, detail: err.Error()}
}

// dialOutcome returns the outcome of a connection that failed with err.
// A local error does not count as a failed connection.
func dialOutcome(err error) outcome {
	o := errOutcome(err)
	o.connectFailed = o.kind != outLocal
	return o
}
