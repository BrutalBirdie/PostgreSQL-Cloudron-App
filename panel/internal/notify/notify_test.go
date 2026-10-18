package notify

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http/httptest"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"
)

type received struct {
	tls                    bool
	auth, from, rcpt, data string
}

// fakeSMTP accepts one message per connection and reports what it got. It
// only offers AUTH after STARTTLS, like Cloudron's mail server on 2587. The
// certificate is valid for 127.0.0.1 and signed by the returned pool.
func fakeSMTP(t *testing.T, rejectRcpt string) (string, *x509.CertPool, chan received) {
	certSrv := httptest.NewUnstartedServer(nil)
	certSrv.StartTLS()
	certSrv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(certSrv.Certificate())
	tlsCfg := &tls.Config{Certificates: certSrv.TLS.Certificates}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	out := make(chan received, 10)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				tp := textproto.NewConn(conn)
				var got received
				tp.PrintfLine("220 fake")
				for {
					line, err := tp.ReadLine()
					if err != nil {
						return
					}
					cmd := strings.ToUpper(strings.Fields(line + " x")[0])
					switch {
					case cmd == "EHLO" && got.tls:
						tp.PrintfLine("250-fake\r\n250 AUTH PLAIN")
					case cmd == "EHLO":
						tp.PrintfLine("250-fake\r\n250 STARTTLS")
					case cmd == "STARTTLS":
						tp.PrintfLine("220 go ahead")
						tc := tls.Server(conn, tlsCfg)
						if tc.Handshake() != nil {
							return
						}
						conn, tp, got.tls = tc, textproto.NewConn(tc), true
					case cmd == "AUTH" && !got.tls:
						tp.PrintfLine("530 must issue STARTTLS first")
					case cmd == "AUTH":
						got.auth = strings.Fields(line)[2]
						tp.PrintfLine("235 ok")
					case cmd == "MAIL":
						got.from = line
						tp.PrintfLine("250 ok")
					case cmd == "RCPT":
						if rejectRcpt != "" && strings.Contains(line, rejectRcpt) {
							tp.PrintfLine("550 no such user")
							continue
						}
						got.rcpt = line
						tp.PrintfLine("250 ok")
					case cmd == "DATA":
						tp.PrintfLine("354 go")
						b, _ := tp.ReadDotBytes()
						got.data = string(b)
						tp.PrintfLine("250 ok")
						out <- got
					case cmd == "QUIT":
						tp.PrintfLine("221 bye")
						return
					default:
						tp.PrintfLine("250 ok")
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), roots, out
}

func mailEnv(t *testing.T, addr string) {
	host, port, _ := net.SplitHostPort(addr)
	t.Setenv("CLOUDRON_MAIL_SMTP_SERVER", host)
	t.Setenv("CLOUDRON_MAIL_STARTTLS_PORT", port)
	t.Setenv("CLOUDRON_MAIL_SMTP_USERNAME", "app")
	t.Setenv("CLOUDRON_MAIL_SMTP_PASSWORD", "secret")
	t.Setenv("CLOUDRON_MAIL_FROM", "pg.app@example.test")
	t.Setenv("CLOUDRON_MAIL_FROM_DISPLAY_NAME", "")
}

func TestSend(t *testing.T) {
	addr, roots, got := fakeSMTP(t, "bad@")
	mailEnv(t, addr)
	m := FromEnv()
	if m == nil {
		t.Fatal("mailer not configured")
	}
	m.roots = roots
	sent, err := m.Send(context.Background(), []string{"ann@example.test", "bad@example.test"}, "PostgreSQL: snapshot of äpp failed", "line one\nline two . with ümlaut\n.\n")
	if sent != 1 || err == nil || !strings.Contains(err.Error(), "bad@example.test") {
		t.Fatalf("sent %d err %v", sent, err)
	}
	r := <-got
	if !r.tls {
		t.Error("message sent without TLS")
	}
	if auth, _ := base64.StdEncoding.DecodeString(r.auth); string(auth) != "\x00app\x00secret" {
		t.Errorf("auth %q", auth)
	}
	if !strings.Contains(r.from, "<pg.app@example.test>") || !strings.Contains(r.rcpt, "<ann@example.test>") {
		t.Errorf("envelope %q %q", r.from, r.rcpt)
	}
	msg, err := mail.ReadMessage(bufio.NewReader(strings.NewReader(r.data)))
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject")); s != "PostgreSQL: snapshot of äpp failed" {
		t.Errorf("subject %q", s)
	}
	if from := msg.Header.Get("From"); from != `"PostgreSQL Server" <pg.app@example.test>` {
		t.Errorf("from %q", from)
	}
	body, err := io.ReadAll(quotedprintable.NewReader(msg.Body))
	// ReadDotBytes turns CRLF into LF
	if err != nil || string(body) != "line one\nline two . with ümlaut\n.\n" {
		t.Errorf("body %q %v", body, err)
	}
}

func TestUntrustedCertificate(t *testing.T) {
	addr, _, _ := fakeSMTP(t, "")
	mailEnv(t, addr)
	m := FromEnv()
	m.roots = x509.NewCertPool()
	if _, err := m.Send(context.Background(), []string{"ann@example.test"}, "s", "b"); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("untrusted certificate accepted: %v", err)
	}
}

func TestNotConfigured(t *testing.T) {
	t.Setenv("CLOUDRON_MAIL_SMTP_SERVER", "")
	if FromEnv() != nil {
		t.Fatal("mailer without env")
	}
	var m *Mailer
	if _, err := m.Send(context.Background(), []string{"a@b.c"}, "s", "b"); err == nil {
		t.Fatal("nil mailer sent")
	}
}

func TestParseList(t *testing.T) {
	got, err := ParseList(" a@example.test, Bob <b@example.test> ")
	if err != nil || len(got) != 2 || got[0] != "a@example.test" || got[1] != "b@example.test" {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := ParseList("  "); err != nil || got != nil {
		t.Fatalf("empty: %v %v", got, err)
	}
	if _, err := ParseList("not an address\r\nBcc: x@y.z"); err == nil {
		t.Fatal("invalid list accepted")
	}
}
