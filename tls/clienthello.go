package tls

import (
	"crypto/rand"
    "encoding/hex"
)

func makeClientHello(conn *TLSConn, hostname string) ([]byte, error) {
	b := make([]byte, 0)

	// legacy_version
	b = append(b, "\x03\x03"...)

	// random
	_, err := rand.Read(conn.clientRandom[:])
	if err != nil {
		return nil, err
	}
	b = append(b, conn.clientRandom[:]...)

	// legacy_session_id
	b = append(b, 0x00)

	// cipher suites
	b = appendLen16(b, 2)
	b = append(b, kTLS_AES_128_GCM_SHA256...)

	// legacy_compression_methods
	b = append(b, 0x01)
	b = append(b, 0x00)

	// extensions
	exts := make([]byte, 0)

	// extension - supported versions
	exts = append(exts, to16(kEXT_SUPPORTED_VERSIONS)...)
	exts = appendLen16(exts, 3)
	exts = appendLen8(exts, 2)
	exts = append(exts, kTLS_VERSION_13...)

	// extension - supported groups
	exts = append(exts, to16(kEXT_SUPPORTED_GROUPS)...)
	exts = appendLen16(exts, 10)
	exts = appendLen16(exts, 8)
	exts = append(exts, kEXT_SUPPORTED_GROUPS_SECP256R1...)
	exts = append(exts, kEXT_SUPPORTED_GROUPS_SECP384R1...)
	exts = append(exts, kEXT_SUPPORTED_GROUPS_SECP521R1...)
	exts = append(exts, kEXT_SUPPORTED_GROUPS_X25519...)

	// extension - key share
    x25519pub, _ := hex.DecodeString("358072D6365880D1AEEA329ADF9121383851ED21A28E3B75E965D0D2CD166254");
    secp256r1pub, _ := hex.DecodeString("04FE92414A8389E7273BE51E3A88F2C627E3CD5BCEC849B99CBD7A2B85AB" +
                "080015506A6B7F67A2C51A8BFD17565B841B4CB760682F3DEB96B2E64B6D30A479879A");
    secp384r1pub, _ := hex.DecodeString("049BCDA96FEDA896AC27B59335CB19635697E82D15C0EFD0CA13F94B6832" +
                "20087EAA96BDFBA9253B3957C95E7841590015CE8F9E271FE8773455439E84F65CCC73716795362712F1" + 
                "089632C50C5BE44D9FC621940C2242CED508C828CACF6A68D7");
    secp521r1pub, _ := hex.DecodeString("049BCDA96FEDA896AC27B59335CB19635697E82D15C0EFD0CA13F94B6832" + 
                "20087EAA96BDFBA9253B3957C95E7841590015CE8F9E271FE8773455439E84F65CCC73716795362712F1" +
                "089632C50C5BE44D9FC621940C2242CED508C828CACF6A68D7");
    
	copy(conn.clientPubKey[:], x25519pub[:])
	exts = append(exts, to16(kEXT_KEY_SHARE)...)
	exts = appendLen16(exts, 2 + len(secp256r1pub)+2+2 + len(secp384r1pub)+2+2 +
        len(secp521r1pub)+2+2 /*+ len(x25519pub)+2+2*/)
	exts = appendLen16(exts, len(secp256r1pub)+2+2 + len(secp384r1pub)+2+2 +
        len(secp521r1pub)+2+2 /*+ len(x25519pub)+2+2*/)

    /// first choice, secp256r1
	exts = append(exts, kEXT_SUPPORTED_GROUPS_SECP256R1...)
	exts = appendLen16(exts, len(secp256r1pub))
	exts = append(exts, secp256r1pub[:]...)

    /// second choice, secp384r1
	exts = append(exts, kEXT_SUPPORTED_GROUPS_SECP384R1...)
	exts = appendLen16(exts, len(secp384r1pub))
	exts = append(exts, secp384r1pub[:]...)

    /// third choice, secp521r1
	exts = append(exts, kEXT_SUPPORTED_GROUPS_SECP521R1...)
	exts = appendLen16(exts, len(secp521r1pub))
	exts = append(exts, secp521r1pub[:]...)

    /// finally, x25519
/*
	exts = append(exts, kEXT_SUPPORTED_GROUPS_X25519...)
	exts = appendLen16(exts, len(x25519pub))
	exts = append(exts, x25519pub[:]...)
*/


	// extension - server name
	exts = append(exts, to16(kEXT_SERVER_NAME)...)
	exts = appendLen16(exts, len(hostname)+5)
	exts = appendLen16(exts, len(hostname)+3)
	exts = append(exts, kEXT_SERVER_NAME_HOST)
	exts = appendLen16(exts, len(hostname))
	exts = append(exts, hostname...)

	// extension - signature algorithms
	exts = append(exts, to16(kEXT_SIGNATURE_ALGORITHMS)...)
	exts = appendLen16(exts, 8)
	exts = appendLen16(exts, 6)
	// we're not going to check the signature anyway, so advertise all the requireds
	exts = append(exts, kTLS_RSA_PKCS1_SHA256...)
	exts = append(exts, kTLS_ECDSA_SECP256R1_SHA256...)
	exts = append(exts, kTLS_RSA_PSS_RSAE_SHA256...)

	// append extensions to our handshake
	b = appendLen16(b, len(exts))
	b = append(b, exts...)

	// wrap as handshake type: client_hello
	hs := make([]byte, 0)
	hs = append(hs, kHS_TYPE_CLIENT_HELLO)
	hs = appendLen24(hs, len(b))
	hs = append(hs, b...)

	// wrap as record type: handshake
	rec := make([]byte, 0)
	rec = append(rec, kREC_TYPE_HANDSHAKE)
	rec = append(rec, kTLS_VERSION_12...)
	rec = appendLen16(rec, len(hs))
	rec = append(rec, hs...)

	return rec, nil
}

func appendLen8(b []byte, len int) []byte {
	return append(b, byte(len))
}

func appendLen16(b []byte, len int) []byte {
	b = append(b, byte(len>>8))
	return append(b, byte(len))
}

func appendLen24(b []byte, len int) []byte {
	b = append(b, byte(len>>16))
	b = append(b, byte(len>>8))
	return append(b, byte(len))
}

func to16(num int) []byte {
	return []byte{byte(num << 8), byte(num)}
}
