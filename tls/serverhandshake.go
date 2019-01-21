package tls

import (
    "errors"
    "encoding/hex"
)

func readNum(bits int, b []byte) uint {
	x := uint(0)
	for i := 0; i < bits; i += 8 {
		x <<= 8
		x |= uint(b[i/8])
	}
	return x
}

func readVec(lenBits int, payload []byte) (vec []byte, rest []byte) {
	len := readNum(lenBits, payload)
	return payload[uint(lenBits/8) : uint(lenBits/8)+len], payload[uint(lenBits/8)+len:]
}

func match(c []byte, payload []byte) bool {
	for i := range c {
		if c[i] != payload[i] {
			return false
		}
	}
	return true
}

func handleServerHello(payload []byte) (result string, err error) {
    orig := payload

    // handshake header
    payload = payload[4:]

	// version
	payload = payload[2:]

	// server random
	if match(kHS_HELLO_RETRY_REQUEST, payload) {
        return "", errors.New("server sent HelloRetryRequest [" + hex.EncodeToString(orig) + "]")
	}
	payload = payload[32:]

	// session id
	_, payload = readVec(8, payload)

	// cipher suite
	if !match(kTLS_AES_128_GCM_SHA256, payload) {
        return "", errors.New("wrong cipher")
	}
	payload = payload[2:]

	// compression method
	if payload[0] != 0x00 {
		return "", errors.New("wrong compression method")
	}
	payload = payload[1:]

	// extensions
	exts, payload := readVec(16, payload)
	result = parseExtensions(exts)

	if len(payload) != 0 {
		return "", errors.New("unexpected suffix")
	}
    return result, nil
}

func parseExtensions(exts []byte) (result string) {
	for len(exts) > 0 {
		typ := int(exts[0])<<8 | int(exts[1])
		var ext []byte
		ext, exts = readVec(16, exts[2:])
        r := ""
		switch typ {
		case kEXT_SUPPORTED_GROUPS:
			r = parseExtSupportedGroups(ext)
		case kEXT_KEY_SHARE:
			r = parseExtKeyShare(ext)
		case kEXT_SUPPORTED_VERSIONS:
			r = parseExtSupportedVersions(ext)
		case kEXT_SERVER_NAME:
			r = parseExtServerName(ext)
		default:
			panic("unknown ext type")
		}
        if len(r) > 0 {
            result = r
        }
	}
    return
}

func parseExtKeyShare(payload []byte) (result string) {
	if match(kEXT_SUPPORTED_GROUPS_X25519, payload) {
        result = "x25519"
	} else if match(kEXT_SUPPORTED_GROUPS_SECP256R1, payload) {
        result = "SECP256r1"
	} else if match(kEXT_SUPPORTED_GROUPS_SECP384R1, payload) {
        result = "SECP384r1"
	} else if match(kEXT_SUPPORTED_GROUPS_SECP521R1, payload) {
        result = "SECP521r1"
    }

	payload = payload[2:]
	_, payload = readVec(16, payload)
	if len(payload) != 0 {
		panic("bad key share length")
	}
    return
}

func parseExtSupportedVersions(payload []byte) (result string) {
	if !match(kTLS_VERSION_13, payload) {
		panic("bad supported version")
	}
    return ""
}

func parseExtSupportedGroups(payload []byte) (result string) {
	// the server advises its preferred groups, for use in subsequent connections
    return ""
}

func parseExtServerName(payload []byte) (result string) {
	// not sure why tls13.crypto.mozilla.org sends this (empty) extension
    return ""
}
