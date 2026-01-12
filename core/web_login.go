package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

var ERR_NEXT_AUTH_SMS = errors.New("SMS Code required")
var ERR_NEXT_AUTH_TOTP = errors.New("Current user's TOTP bound")

func WebLogin(server string, username string, password string) (string, error) {
	server = "https://" + server

	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}

	addr := server + "/por/login_auth.csp?apiversion=1"
	Log("[LOGIN]", "Connecting to %s...", server[8:]) // strip "https://"

	resp, err := c.Get(addr)
	if err != nil {
		debug.PrintStack()
		return "", err
	}

	defer resp.Body.Close()

	buf := make([]byte, 40960)
	n, _ := resp.Body.Read(buf)

	twfId := string(regexp.MustCompile(`<TwfID>(.*)</TwfID>`).FindSubmatch(buf[:n])[1])
	Log("[LOGIN]", "Got session: %s", twfId)

	rsaKey := string(regexp.MustCompile(`<RSA_ENCRYPT_KEY>(.*)</RSA_ENCRYPT_KEY>`).FindSubmatch(buf[:n])[1])

	rsaExpMatch := regexp.MustCompile(`<RSA_ENCRYPT_EXP>(.*)</RSA_ENCRYPT_EXP>`).FindSubmatch(buf[:n])
	rsaExp := ""
	if rsaExpMatch != nil {
		rsaExp = string(rsaExpMatch[1])
	} else {
		LogWarn("No RSA_ENCRYPT_EXP found, using default 65537")
		rsaExp = "65537"
	}

	csrfMatch := regexp.MustCompile(`<CSRF_RAND_CODE>(.*)</CSRF_RAND_CODE>`).FindSubmatch(buf[:n])
	csrfCode := ""
	if csrfMatch != nil {
		csrfCode = string(csrfMatch[1])
		password += "_" + csrfCode
	} else {
		LogWarn("No CSRF code found, maybe connecting to an older server")
	}

	Log("[LOGIN]", "Encrypting credentials...")

	pubKey := rsa.PublicKey{}
	pubKey.E, _ = strconv.Atoi(rsaExp)
	moduls := big.Int{}
	moduls.SetString(rsaKey, 16)
	pubKey.N = &moduls

	encryptedPassword, err := rsa.EncryptPKCS1v15(rand.Reader, &pubKey, []byte(password))
	if err != nil {
		debug.PrintStack()
		return "", err
	}
	encryptedPasswordHex := hex.EncodeToString(encryptedPassword)

	addr = server + "/por/login_psw.csp?anti_replay=1&encrypt=1&type=cs"
	Log("[LOGIN]", "Authenticating user...")

	form := url.Values{
		"svpn_rand_code":    {""},
		"mitm":              {""},
		"svpn_req_randcode": {csrfCode},
		"svpn_name":         {username},
		"svpn_password":     {encryptedPasswordHex},
	}

	req, err := http.NewRequest("POST", addr, strings.NewReader(form.Encode()))
	req.Header.Set("Cookie", "TWFID="+twfId)

	resp, err = c.Do(req)
	if err != nil {
		debug.PrintStack()
		return "", err
	}

	n, _ = resp.Body.Read(buf)
	defer resp.Body.Close()

	// SMS Code Process
	if strings.Contains(string(buf[:n]), "<NextService>auth/sms</NextService>") || strings.Contains(string(buf[:n]), "<NextAuth>2</NextAuth>") {
		Log("[LOGIN]", "SMS code required")

		addr = server + "/por/login_sms.csp?apiversion=1"
		req, err = http.NewRequest("POST", addr, nil)
		req.Header.Set("Cookie", "TWFID="+twfId)

		resp, err = c.Do(req)
		if err != nil {
			debug.PrintStack()
			return "", err
		}

		n, _ := resp.Body.Read(buf)
		defer resp.Body.Close()

		if !strings.Contains(string(buf[:n]), "验证码已发送到您的手机") && !strings.Contains(string(buf[:n]), "<USER_PHONE>") {
			debug.PrintStack()
			return "", errors.New("unexpected sms resp: " + string(buf[:n]))
		}

		Log("[LOGIN]", "SMS code sent, waiting for input...")

		return twfId, ERR_NEXT_AUTH_SMS
	}

	// TOTP Authentication Process
	if strings.Contains(string(buf[:n]), "<NextService>auth/token</NextService>") || strings.Contains(string(buf[:n]), "<NextServiceSubType>totp</NextServiceSubType>") {
		Log("[LOGIN]", "TOTP authentication required")
		return twfId, ERR_NEXT_AUTH_TOTP
	}

	if strings.Contains(string(buf[:n]), "<NextAuth>-1</NextAuth>") || !strings.Contains(string(buf[:n]), "<NextAuth>") {
		// No additional auth required, continue
	} else {
		debug.PrintStack()
		return "", errors.New("Not implemented auth: " + string(buf[:n]))
	}

	if !strings.Contains(string(buf[:n]), "<Result>1</Result>") {
		debug.PrintStack()
		return "", errors.New("Login FAILED: " + string(buf[:n]))
	}

	twfIdMatch := regexp.MustCompile(`<TwfID>(.*)</TwfID>`).FindSubmatch(buf[:n])
	if twfIdMatch != nil {
		twfId = string(twfIdMatch[1])
	}

	LogSuccess("[LOGIN]", "✓ Authentication successful")

	return twfId, nil
}

func AuthSms(server string, username string, password string, twfId string, smsCode string) (string, error) {
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}

	buf := make([]byte, 40960)

	addr := "https://" + server + "/por/login_sms1.csp?apiversion=1"
	Log("[LOGIN]", "Verifying SMS code...")
	form := url.Values{
		"svpn_inputsms": {smsCode},
	}

	req, err := http.NewRequest("POST", addr, strings.NewReader(form.Encode()))
	req.Header.Set("Cookie", "TWFID="+twfId)

	resp, err := c.Do(req)
	if err != nil {
		debug.PrintStack()
		return "", err
	}

	n, _ := resp.Body.Read(buf)
	defer resp.Body.Close()

	if !strings.Contains(string(buf[:n]), "Auth sms suc") {
		debug.PrintStack()
		return "", errors.New("SMS Code verification FAILED: " + string(buf[:n]))
	}

	twfId = string(regexp.MustCompile(`<TwfID>(.*)</TwfID>`).FindSubmatch(buf[:n])[1])
	LogSuccess("[LOGIN]", "✓ SMS verification successful")

	return twfId, nil
}

func TOTPAuth(server string, username string, password string, twfId string, TOTPCode string) (string, error) {
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}

	buf := make([]byte, 40960)

	addr := "https://" + server + "/por/login_token.csp"
	Log("[LOGIN]", "Verifying TOTP code...")
	form := url.Values{
		"svpn_inputtoken": {TOTPCode},
	}

	req, err := http.NewRequest("POST", addr, strings.NewReader(form.Encode()))
	req.Header.Set("Cookie", "TWFID="+twfId)

	resp, err := c.Do(req)
	if err != nil {
		debug.PrintStack()
		return "", err
	}

	n, _ := resp.Body.Read(buf)
	defer resp.Body.Close()

	if !strings.Contains(string(buf[:n]), "suc") {
		debug.PrintStack()
		return "", errors.New("TOTP token verification FAILED: " + string(buf[:n]))
	}

	twfId = string(regexp.MustCompile(`<TwfID>(.*)</TwfID>`).FindSubmatch(buf[:n])[1])
	LogSuccess("[LOGIN]", "✓ TOTP verification successful")

	return twfId, nil
}

func ECAgentToken(server string, twfId string) (string, error) {
	Log("[AGENT]", "Fetching ECAgent token...")

	dialConn, err := net.Dial("tcp", server)
	if err != nil {
		return "", err
	}
	defer dialConn.Close()
	conn := utls.UClient(dialConn, &utls.Config{InsecureSkipVerify: true}, utls.HelloGolang)
	defer conn.Close()

	// When you establish a HTTPS connection to server and send a valid request with TWFID,
	// the TLS ServerHello SessionId is the first part of token
	io.WriteString(conn, "GET /por/conf.csp HTTP/1.1\r\nHost: "+server+"\r\nCookie: TWFID="+twfId+"\r\n\r\nGET /por/rclist.csp HTTP/1.1\r\nHost: "+server+"\r\nCookie: TWFID="+twfId+"\r\n\r\n")

	buf := make([]byte, 40960)
	totalRead := 0
	// Read all response data. A single Read() may not retrieve the complete
	// response on some platforms (e.g. Windows), causing subsequent requests to fail.
	for {
		n, err := conn.Read(buf[totalRead:])
		totalRead += n
		if err != nil {
			break
		}
		if totalRead >= len(buf) {
			break
		}
	}

	if totalRead == 0 {
		debug.PrintStack()
		return "", errors.New("ECAgent Request invalid: no response")
	}

	LogSuccess("[AGENT]", "✓ Token acquired")

	return hex.EncodeToString(conn.HandshakeState.ServerHello.SessionId)[:31] + "\x00", nil
}
