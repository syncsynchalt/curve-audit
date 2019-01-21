package tls

import (
    "net"
)

const (
	kX25519KeyLen = 32
	kSHA256OutLen = 32
	kAES128KeyLen = 16
	kGCMIVLen     = 12
)

type TLSConn struct {
	raw            net.Conn
	clientRandom   [32]byte
	clientPrivKey  [kX25519KeyLen]byte
	clientPubKey   [kX25519KeyLen]byte
	serverRandom   [32]byte
	serverPubKey   [kX25519KeyLen]byte
	transcript     []byte
	lastTranscript []byte
	secret0        [32]byte
	masterSecret   [kSHA256OutLen]byte
	serverSeq      uint64
	clientSeq      uint64
	clientWriteKey [kAES128KeyLen]byte
	serverWriteKey [kAES128KeyLen]byte
	clientWriteIV  [kGCMIVLen]byte
	serverWriteIV  [kGCMIVLen]byte

	clientHandshakeTrafficSecret   [kSHA256OutLen]byte
	serverHandshakeTrafficSecret   [kSHA256OutLen]byte
	clientApplicationTrafficSecret [kSHA256OutLen]byte
	serverApplicationTrafficSecret [kSHA256OutLen]byte

	readBuf  []byte
	writeBuf []byte
}

type action int

const (
	action_none           = action(0)
	action_reset_sequence = action(1 << iota)
	action_send_finished  = action(1 << iota)
)

func CheckCurve(raw net.Conn, hostname string) (string, error) {
	conn := &TLSConn{raw: raw}
	rec, err := makeClientHello(conn, hostname)
	if err != nil {
        return "", err
	}
	err = writeHandshakeRecord(conn, rec)
	if err != nil {
		return "", err
	}

	serverHello, err := conn.readRecord()
	if err != nil {
        return "", err
	}
    result, err := handleServerHello(serverHello)
    if err != nil {
        return "", err
    }

    return result, nil
}

func writeHandshakeRecord(conn *TLSConn, rec []byte) error {
	n, err := conn.raw.Write(rec)
	if err != nil {
		return err
	}
	if n != len(rec) {
		panic("short write")
	}
	conn.addToTranscript(rec[5:])
	return nil
}

func (conn *TLSConn) readRaw(b []byte) error {
	for len(b) > 0 {
		n, err := conn.raw.Read(b)
		b = b[n:]
		if err != nil {
			return err
		}
	}
	return nil
}

func (conn *TLSConn) writeRaw(b []byte) error {
	for len(b) > 0 {
		n, err := conn.raw.Write(b)
		b = b[n:]
		if err != nil {
			return err
		}
	}
	return nil
}

func (conn *TLSConn) Read(b []byte) (n int, err error) {
	if len(conn.readBuf) == 0 {
		_, err = conn.readRecord()
		if err != nil {
			return 0, err
		}
	}
	l := len(conn.readBuf)
	if l > len(b) {
		l = len(b)
	}
	copy(b[:l], conn.readBuf)
	conn.readBuf = conn.readBuf[l:]
	if len(conn.readBuf) == 0 {
		// reclaim memory
		conn.readBuf = nil
	}
	return l, nil
}

func (conn *TLSConn) readRecord() ([]byte, error) {
	hdrbuf := make([]byte, 5)
	err := conn.readRaw(hdrbuf)
	if err != nil {
		return nil, err
	}
	length := readNum(16, hdrbuf[3:])
	payload := make([]byte, length)
	err = conn.readRaw(payload)
	if err != nil {
		return nil, err
	}
    return payload, nil
}

func lastByte(bb []byte) (last byte, rest []byte) {
	if len(bb) == 0 {
		panic("lastbyte on empty record")
	}
	b := bb[len(bb)-1]
	return b, bb[:len(bb)-1]
}

func (conn *TLSConn) Close() (err error) {
	return conn.raw.Close()
}

func (conn *TLSConn) addToTranscript(hsr []byte) {
	conn.lastTranscript = conn.transcript
	conn.transcript = append(conn.transcript, hsr...)
}
