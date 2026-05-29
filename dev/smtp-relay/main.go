package main

import (
	"bytes"
	"log"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strings"

	"github.com/mhale/smtpd"
)

const (
	upstreamHost = "smtp.sendgrid.net"
	upstreamAddr = "smtp.sendgrid.net:587"
	sgUsername   = "apikey" // literal — SendGrid SMTP convention
)

var sgApiKey = os.Getenv("SENDGRID_API_KEY")

func main() {
	if sgApiKey == "" {
		log.Fatal("SENDGRID_API_KEY env var is required")
	}
	addr := ":" + envOr("LISTEN_PORT", "25")
	log.Printf("smtp-relay: listening on %s, forwarding to %s", addr, upstreamAddr)
	err := smtpd.ListenAndServe(addr, handle, "mcpmesh-smtp-relay", "")
	if err != nil {
		log.Fatalf("listen failed: %v", err)
	}
}

func handle(_ net.Addr, from string, to []string, data []byte) error {
	// Tag for SendGrid analytics. The header is inert-but-correct when From
	// domain is the shared platform domain (every tenant tagged identically
	// until Phase 2 per-tenant From). Real per-tenant breakdown lands when
	// tenants authenticate their own From domains.
	tenantTag := extractFromDomain(data)
	data = injectSMTPAPIHeader(data, tenantTag)

	auth := smtp.PlainAuth("", sgUsername, sgApiKey, upstreamHost)
	if err := smtp.SendMail(upstreamAddr, auth, from, to, data); err != nil {
		log.Printf("smtp-relay: forward failed (from=%s to=%v): %v", from, to, err)
		return err
	}
	log.Printf("smtp-relay: forwarded (from=%s rcpt=%d tag=%s)", from, len(to), tenantTag)
	return nil
}

func extractFromDomain(data []byte) string {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return "unknown"
	}
	addrs, err := mail.ParseAddressList(msg.Header.Get("From"))
	if err != nil || len(addrs) == 0 {
		return "unknown"
	}
	at := strings.LastIndex(addrs[0].Address, "@")
	if at < 0 || at+1 >= len(addrs[0].Address) {
		return "unknown"
	}
	return addrs[0].Address[at+1:]
}

// injectSMTPAPIHeader prepends an X-SMTPAPI header with a JSON payload that
// SendGrid uses to attach unique_args + categories to the send. SendGrid
// strips the header on egress so the recipient never sees it.
func injectSMTPAPIHeader(data []byte, tenant string) []byte {
	// Header value must be on one logical line; SendGrid accepts compact JSON.
	val := `{"unique_args":{"tenant":"` + jsonEscape(tenant) + `"},"category":["auth-platform"]}`
	header := []byte("X-SMTPAPI: " + val + "\r\n")
	return append(header, data...)
}

func jsonEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
