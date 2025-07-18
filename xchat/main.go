package main

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/gluk256/crypto/algo/keccak"
	"github.com/gluk256/crypto/algo/primitives"
	"github.com/gluk256/crypto/cmd/common"
	"github.com/gluk256/crypto/crutils"
	"github.com/gluk256/elliptic/asym"
)

const (
	PrefixSize = 4
	MacSize    = 8
	SuffixSize = 4 + 8 + 4 + MacSize
)

var (
	MaxFileSize        uint32
	masterKey          []byte
	serverKey          *ecdsa.PrivateKey
	clientKey          *ecdsa.PrivateKey
	ephemeralKey       *ecdsa.PrivateKey
	remoteServerPubKey *ecdsa.PublicKey
)

func cleanup() {
	crutils.AnnihilateData(masterKey)
	asym.AnnihilatePrivateKey(serverKey)
	asym.AnnihilatePrivateKey(clientKey)
	asym.AnnihilatePrivateKey(ephemeralKey)
}

func changeEphemeralKey() bool {
	k, err := asym.GenerateKey()
	if err != nil {
		fmt.Printf("Failed to change ephemeral key: %s \n", err.Error())
	} else {
		asym.AnnihilatePrivateKey(ephemeralKey)
		ephemeralKey = k
		printFingerprint(&ephemeralKey.PublicKey, "Your ephemeral")
	}
	return err == nil
}

func getFileEncryptionKey() []byte {
	return keccak.Digest(masterKey, 256)
}

func loadEncryptionKeys(flags string) (err error) {
	var cert []byte
	if strings.Contains(flags, "M") {
		cert = keccak.Digest([]byte("7c6860a2cbc905d54438e36fbf82772c63519112a6958ebfc4da171d8c55c4bd"), 256)
	} else {
		cert, err = common.LoadCertificate(true)
		masterKey = cert
		if err != nil {
			return err
		}
	}

	sk := keccak.Digest(cert, 32)
	defer crutils.AnnihilateData(sk)
	serverKey, err = asym.ImportPrivateKey(sk)
	if err != nil {
		return err
	}

	if isServer(flags) {
		return nil
	}

	ephemeralKey, err = asym.GenerateKey()
	if err != nil {
		return err
	}

	if strings.Contains(flags, "T") {
		fmt.Println("====================> WARNING: test mode (without password), not safe to use for any other purposes!")
		masterKey[0]++
	} else {
		pass, err := common.GetPassword(flags)
		if err != nil {
			crutils.AnnihilateData(pass)
			return err
		} else {
			masterKey = primitives.XorInplace(masterKey, pass, 256)
			crutils.AnnihilateData(pass)
		}
	}

	ck := keccak.Digest(masterKey, 288)
	ck = ck[256:]
	defer crutils.AnnihilateData(ck)
	clientKey, err = asym.ImportPrivateKey(ck)
	if err != nil {
		return err
	}

	return err
}

func isServer(flags string) bool {
	if len(flags) == 0 {
		return true
	}
	return strings.Contains(flags, "m") || strings.Contains(flags, "M")
}

func getDefaultPort() string {
	return ":26594"
}

func getDefaultIP() string {
	return getLocalIP() + getDefaultPort()
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		fmt.Println("error", err.Error())
		return ""
	}

	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func sendPacket(conn net.Conn, msg []byte) error {
	prefix := make([]byte, PrefixSize)
	binary.LittleEndian.PutUint32(prefix, uint32(len(msg)))
	n, err := conn.Write(prefix)
	if err != nil {
		return err
	}
	if n != PrefixSize {
		return errors.New("message size not sent")
	}

	n, err = conn.Write(msg)
	if err == nil && n != len(msg) {
		err = errors.New("message not sent")
	}

	if err != nil {
		exiting = true
	}

	return err
}

func readNBytes(c net.Conn, sz uint32) ([]byte, error) {
	msg := make([]byte, sz)
	n, err := c.Read(msg)
	if err != nil {
		return nil, err
	}
	if uint32(n) != sz {
		return nil, errors.New("wrong message size")
	}
	return msg, nil
}

func receivePacket(conn net.Conn) ([]byte, error) {
	var msg []byte
	prefix, err := readNBytes(conn, PrefixSize)
	if err == nil {
		sz := binary.LittleEndian.Uint32(prefix)
		if sz > MaxFileSize {
			return nil, errors.New("huge message")
		} else {
			msg, err = readNBytes(conn, sz)
		}
	}
	return msg, err
}

func changeMaxFileSize() {
	i, err := common.GetUint("new file size")
	if err == nil {
		MaxFileSize = i
		fmt.Printf("MaxFileSize = %d \n", MaxFileSize)
	} else {
		fmt.Printf("Error: %s \n", err.Error())
	}
}

func help() {
	fmt.Printf("xchat v.0.%d.2 \n", crutils.CipherVersion)
	fmt.Println("encrypted chat between remote peers, with ephemeral keys and forward secrecy")
	fmt.Println("USAGE: xchat flags [ip_address[:port]] [server_pub_key] [client_pub_key]")
	fmt.Println("\t -m main node (server)")
	fmt.Println("\t -M main node with precompriled certificate")
	fmt.Println("\t -c chat client")
	fmt.Println("\t -l localhost (server-related params are not required)")
	fmt.Println("\t -s secure password")
	fmt.Println("\t -T test mode (without password)")
	fmt.Println("\t -y restart previous session")
	fmt.Println("\t -i initiate new chat session")
	fmt.Println("\t -F allow to receive files")
	fmt.Println("\t -b beep on incoming message")
	fmt.Println("\t -v verbose")
	fmt.Println("\t -h help")
}

func helpInternal() {
	fmt.Println("COMMANDS")
	fmt.Println("\\f: send file")
	fmt.Println("\\F: allow to receive files")
	fmt.Println("\\z: change max file size")
	fmt.Println("\\w: whitelist another peer")
	fmt.Println("\\W: print whitelist")
	fmt.Println("\\y: restart last session")
	fmt.Println("\\i: initiate new chat session with current peer")
	fmt.Println("\\n: initiate new chat session with new peer")
	fmt.Println("\\d: delete another peer form whitelist")
	fmt.Println("\\D: delete current peer form whitelist")
	fmt.Println("\\k: add session key for additional symmetric encryption")
	fmt.Println("\\K: add session key (secure mode)")
	fmt.Println("\\b: beep on incoming message (on/off)")
	fmt.Println("\\v: verbode mode on/off")
	fmt.Println("\\o: output debug info")
	fmt.Println("\\h: help")
	fmt.Println("\\e: exit current session")
	fmt.Println("\\q: quit")
}

func main() {
	MaxFileSize = 20 * 1024 * 1024
	var flags string
	if len(os.Args) > 1 {
		flags = os.Args[1]
	}

	if strings.Contains(flags, "h") {
		help()
		return
	}

	defer cleanup()
	err := loadEncryptionKeys(flags)
	if err != nil {
		fmt.Printf("Failed to load private key: %s \n", err.Error())
		return
	}

	if isServer(flags) {
		runServer()
	} else {
		runClient(flags)
	}
}
