// The account's password: generated once, and sealed for storage in the
// sandbox's own record.
//
// DPAPI (CryptProtectData) is the seal, protected under this process's own
// account rather than a key wuserbox would have to keep somewhere itself.
// The two calls into it -- to seal, in Protect below, and to open, wherever
// CreateProcessWithLogonW needs the password for a run -- both happen as
// the machine's owner: init always runs as them, elevation only raising the
// integrity level of the same account, never changing it. The sandbox
// account is a different security principal with no access to that
// account's DPAPI master key at all, which matters because a file
// permission alone would not have been enough: acl.Protect grants the
// record group.ReadGroup read access like every other file it protects, so
// a sandbox can read the very bytes this produces. What it cannot do is
// call CryptUnprotectData as itself and get anything back -- the seal is
// tied to the account that made it, not to who can reach the file.

package account

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"runtime"
	"unsafe"

	"github.com/PHPCraftdream/wuserbox/internal/win/w32"
)

var (
	procCryptProtectData   = w32.Crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = w32.Crypt32.NewProc("CryptUnprotectData")
)

type dataBlob struct {
	size uint32
	data *byte
}

// passwordLength is comfortably past any local password-length policy this
// design might run under, and long enough that the classes below always
// have room to appear several times over.
const passwordLength = 24

// passwordClasses are upper, lower, digit and symbol, each missing the
// characters ("0", "O", "1", "l", "I") that read the same as one another in
// a terminal -- this password is generated, never typed, but a person
// reading it out to diagnose a stuck run should not have to guess which
// glyph it was.
var passwordClasses = [][]byte{
	[]byte("ABCDEFGHJKLMNPQRSTUVWXYZ"),
	[]byte("abcdefghijkmnpqrstuvwxyz"),
	[]byte("23456789"),
	[]byte("!@#$%^&*-_=+"),
}

// GeneratePassword returns a password strong enough that guessing it costs
// more than the account boundary itself, and built to satisfy Windows'
// default complexity policy -- three of upper, lower, digit and symbol --
// so account creation does not silently depend on the local password policy
// having already been relaxed. Cycling through the four classes and then
// shuffling guarantees every class appears at least once without leaving
// the first four characters predictably one-per-class.
func GeneratePassword() (string, error) {
	out := make([]byte, passwordLength)
	for i := range out {
		class := passwordClasses[i%len(passwordClasses)]
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(class))))
		if err != nil {
			return "", fmt.Errorf("generating a password: %w", err)
		}
		out[i] = class[n.Int64()]
	}
	if err := shuffle(out); err != nil {
		return "", err
	}
	return string(out), nil
}

func shuffle(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("shuffling a password: %w", err)
		}
		j := n.Int64()
		b[i], b[j] = b[j], b[i]
	}
	return nil
}

// Protect seals password with DPAPI under this process's own account, and
// returns it as base64 text fit for a JSON field.
func Protect(password string) (string, error) {
	sealed, err := protect([]byte(password))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Unprotect reverses Protect. It must run as the same account that sealed
// the value, or CryptUnprotectData fails -- that failure is the whole point.
func Unprotect(sealed string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		return "", fmt.Errorf("decoding the stored password: %w", err)
	}
	plain, err := unprotect(raw)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

const cryptUIForbidden = 0x1 // never show a prompt; there is nobody to answer one

func protect(data []byte) ([]byte, error) {
	in := blobOf(data)
	var out dataBlob
	r, _, err := procCryptProtectData.Call(uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0,
		cryptUIForbidden, uintptr(unsafe.Pointer(&out)))
	runtime.KeepAlive(data)
	if r == 0 {
		return nil, fmt.Errorf("sealing the password: %w", err)
	}
	defer w32.Free(uintptr(unsafe.Pointer(out.data))) // CryptProtectData allocates with LocalAlloc
	return copyBlob(out), nil
}

func unprotect(data []byte) ([]byte, error) {
	in := blobOf(data)
	var out dataBlob
	r, _, err := procCryptUnprotectData.Call(uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0,
		cryptUIForbidden, uintptr(unsafe.Pointer(&out)))
	runtime.KeepAlive(data)
	if r == 0 {
		return nil, fmt.Errorf("unsealing the password: %w", err)
	}
	defer w32.Free(uintptr(unsafe.Pointer(out.data)))
	return copyBlob(out), nil
}

func blobOf(data []byte) dataBlob {
	b := dataBlob{size: uint32(len(data))}
	if len(data) > 0 {
		b.data = &data[0]
	}
	return b
}

func copyBlob(b dataBlob) []byte {
	if b.size == 0 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice(b.data, b.size)...)
}
