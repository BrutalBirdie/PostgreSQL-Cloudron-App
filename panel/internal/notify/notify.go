// Package notify sends mail through the Cloudron sendmail addon.
// https://docs.cloudron.io/packaging/addons#sendmail
package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"time"
)

type Mailer struct {
	addr     string
	host     string
	username string
	password string
	from     mail.Address
	roots    *x509.CertPool // nil uses the system roots
}

// FromEnv returns nil when the sendmail addon is not configured. With
// requiresValidCertificate the server is the mail FQDN and the STARTTLS port
// presents its certificate.
func FromEnv() *Mailer {
	host, port, from := os.Getenv("CLOUDRON_MAIL_SMTP_SERVER"), os.Getenv("CLOUDRON_MAIL_STARTTLS_PORT"), os.Getenv("CLOUDRON_MAIL_FROM")
	if host == "" || port == "" || from == "" {
		return nil
	}
	name := os.Getenv("CLOUDRON_MAIL_FROM_DISPLAY_NAME")
	if name == "" {
		name = "PostgreSQL Server"
	}
	return &Mailer{
		addr:     net.JoinHostPort(host, port),
		host:     host,
		username: os.Getenv("CLOUDRON_MAIL_SMTP_USERNAME"),
		password: os.Getenv("CLOUDRON_MAIL_SMTP_PASSWORD"),
		from:     mail.Address{Name: name, Address: from},
	}
}

// ParseList parses a comma separated list of addresses, "" gives an empty list.
func ParseList(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	list, err := mail.ParseAddressList(s)
	if err != nil {
		return nil, fmt.Errorf("%q is not a list of email addresses", s)
	}
	out := make([]string, len(list))
	for i, a := range list {
		out[i] = a.Address
	}
	return out, nil
}

// Send delivers one message per recipient, so owners do not see each other's
// addresses. It returns how many were sent and the errors of the others.
func (m *Mailer) Send(ctx context.Context, to []string, subject, body string) (int, error) {
	if m == nil {
		return 0, errors.New("outgoing mail is not configured")
	}
	sent := 0
	var errs []error
	for _, rcpt := range to {
		if err := m.send(ctx, rcpt, subject, body); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", rcpt, err))
			continue
		}
		sent++
	}
	return sent, errors.Join(errs...)
}

func (m *Mailer) send(ctx context.Context, rcpt, subject, body string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", m.addr)
	if err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if err := c.StartTLS(&tls.Config{ServerName: m.host, RootCAs: m.roots, MinVersion: tls.VersionTLS12}); err != nil {
		return fmt.Errorf("STARTTLS: %w", err)
	}
	if m.username != "" {
		if err := c.Auth(smtp.PlainAuth("", m.username, m.password, m.host)); err != nil {
			return err
		}
	}
	if err := c.Mail(m.from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(rcpt); err != nil {
		return err
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(m.message(rcpt, subject, body)); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (m *Mailer) message(rcpt, subject, body string) []byte {
	id := make([]byte, 12)
	rand.Read(id)
	_, domain, _ := strings.Cut(m.from.Address, "@")
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", m.from.String())
	fmt.Fprintf(&b, "To: %s\r\n", (&mail.Address{Address: rcpt}).String())
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(id), domain)
	b.WriteString("Auto-Submitted: auto-generated\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	qp := quotedprintable.NewWriter(&b)
	qp.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
	qp.Close()
	return b.Bytes()
}
