package core

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"runtime/debug"

	tls "github.com/refraction-networking/utls"
)

func DumpHex(buf []byte) {
	stdoutDumper := hex.Dumper(os.Stdout)
	defer stdoutDumper.Close()
	stdoutDumper.Write(buf)
}

func TLSConn(server string) (*tls.UConn, error) {
	// dial vpn server
	dialConn, err := net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}

	// using uTLS to construct a weird TLS Client Hello (required by Sangfor)
	// The VPN and HTTP Server share port 443, Sangfor uses a special SessionId to distinguish them. (which is very stupid...)
	conn := tls.UClient(dialConn, &tls.Config{InsecureSkipVerify: true}, tls.HelloCustom)

	random := make([]byte, 32)
	rand.Read(random) // Ignore the err
	conn.SetClientRandom(random)
	conn.SetTLSVers(tls.VersionTLS11, tls.VersionTLS11, []tls.TLSExtension{})
	conn.HandshakeState.Hello.Vers = tls.VersionTLS11
	conn.HandshakeState.Hello.CipherSuites = []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV}
	conn.HandshakeState.Hello.CompressionMethods = []uint8{0}
	conn.HandshakeState.Hello.SessionId = []byte{'L', '3', 'I', 'P', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	return conn, nil
}

func QueryIp(server string, token *[48]byte) ([]byte, *tls.UConn, error) {
	Log("[VPN]", "Connecting to %s...", server)

	conn, err := TLSConn(server)
	if err != nil {
		debug.PrintStack()
		return nil, nil, err
	}
	// Query IP conn CAN NOT be closed, otherwise tx/rx handshake will fail

	LogSuccess("[VPN]", "✓ TLS handshake successful")
	Log("[VPN]", "Querying IP address...")

	// QUERY IP PACKET
	message := []byte{0x00, 0x00, 0x00, 0x00}
	message = append(message, token[:]...)
	message = append(message, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff}...)

	_, err = conn.Write(message)
	if err != nil {
		debug.PrintStack()
		return nil, nil, err
	}

	reply := make([]byte, 0x80)
	_, err = conn.Read(reply)
	if err != nil {
		debug.PrintStack()
		return nil, nil, err
	}

	if reply[0] != 0x00 {
		debug.PrintStack()
		return nil, nil, errors.New("unexpected query ip reply")
	}

	return reply[4:8], conn, nil
}

func BlockRXStream(server string, token *[48]byte, ipRev *[4]byte, ep *EasyConnectEndpoint, debugDump bool) error {
	conn, err := TLSConn(server)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// RECV STREAM START
	message := []byte{0x06, 0x00, 0x00, 0x00}
	message = append(message, token[:]...)
	message = append(message, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
	message = append(message, ipRev[:]...)

	_, err = conn.Write(message)
	if err != nil {
		return err
	}

	reply := make([]byte, 1500)
	_, err = conn.Read(reply)
	if err != nil {
		return err
	}

	if reply[0] != 0x01 {
		return errors.New("unexpected recv handshake reply")
	}

	LogSuccess("[VPN]", "✓ RX handshake successful")

	for {
		n, err := conn.Read(reply)

		if err != nil {
			return err
		}

		ep.WriteTo(reply[:n])

		if debugDump {
			Log("[VPN]", "RX: %d bytes", n)
			DumpHex(reply[:n])
		}
	}
}

func BlockTXStream(server string, token *[48]byte, ipRev *[4]byte, ep *EasyConnectEndpoint, debugDump bool) error {
	conn, err := TLSConn(server)
	if err != nil {
		return err
	}
	defer conn.Close()

	// SEND STREAM START
	message := []byte{0x05, 0x00, 0x00, 0x00}
	message = append(message, token[:]...)
	message = append(message, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
	message = append(message, ipRev[:]...)

	_, err = conn.Write(message)
	if err != nil {
		return err
	}

	reply := make([]byte, 1500)
	_, err = conn.Read(reply)
	if err != nil {
		return err
	}

	if reply[0] != 0x02 {
		return errors.New("unexpected send handshake reply")
	}

	LogSuccess("[VPN]", "✓ TX handshake successful")

	errCh := make(chan error)

	ep.OnRecv = func(buf []byte) {
		n, err := conn.Write(buf)
		if err != nil {
			errCh <- err
			return
		}

		if debugDump {
			Log("[VPN]", "TX: %d bytes", n)
			DumpHex([]byte(buf[:n]))
		}
	}

	return <-errCh
}

func StartProtocol(endpoint *EasyConnectEndpoint, server string, token *[48]byte, ipRev *[4]byte, debugDump bool) {
	RX := func() {
		counter := 0
		for counter < 5 {
			err := BlockRXStream(server, token, ipRev, endpoint, debugDump)
			if err != nil {
				LogWarn("RX stream error, retrying (%d/5): %s", counter+1, err.Error())
			}
			counter += 1
		}
		panic("recv retry limit exceeded.")
	}

	go RX()

	TX := func() {
		counter := 0
		for counter < 5 {
			err := BlockTXStream(server, token, ipRev, endpoint, debugDump)
			if err != nil {
				LogWarn("TX stream error, retrying (%d/5): %s", counter+1, err.Error())
			}
			counter += 1
		}
		panic("send retry limit exceeded.")
	}

	go TX()

	LogSuccess("[VPN]", "✓ Tunnel established")
}
