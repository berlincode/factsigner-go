package factsigner

import (
    "fmt"
    "strconv"
    "github.com/ethereum/go-ethereum/crypto"
    "crypto/ecdsa"
    "golang.org/x/crypto/sha3"
    "encoding/hex"
    "strings"
    "errors"
    "math/big"
)


func HexString2Bytes(str string) []byte {
    str = strings.TrimPrefix(strings.ToLower(str), "0x")

    if len(str)%2 == 1 {
        str = "0" + str
    }

    b, _ := hex.DecodeString(str)
    return b
}

type Signature struct {
    R [32]byte
    S [32]byte
    V uint8
}

type Facts struct {
    underlyingString string
}

func Sign(message []byte, privkey *ecdsa.PrivateKey) Signature {

    validationMsg := "\x19Factsigner Signed Message:\n" + strconv.Itoa(len(message))// + message

    hash := sha3.NewLegacyKeccak256()
    hash.Write([]byte(validationMsg))
    hash.Write(message)
    hashRaw := hash.Sum(nil)

    signature, err := crypto.Sign(hashRaw, privkey)
    if err != nil {
        panic(err)
    }

    var r [32]byte;
    var s [32]byte;
    copy(r[:], signature[:32])
    copy(s[:], signature[32:64])
    return Signature{
        R: r,
        S: s,
        V: signature[64]+27} // add 27, weird Ethereum quirk
}

func NewPrivateKey(privateKeyBytes []byte) (*ecdsa.PrivateKey, error) {
    priv := new(ecdsa.PrivateKey)
    priv.PublicKey.Curve = crypto.S256()
    if 8*len(privateKeyBytes) != priv.Params().BitSize {
            return nil, fmt.Errorf("invalid length, need %d bits", priv.Params().BitSize)
    }
    priv.D = new(big.Int).SetBytes(privateKeyBytes)

    // The priv.D must < N
    //if priv.D.Cmp(crypto.S256().N) >= 0 {
    //        return nil, fmt.Errorf("invalid private key, >=N")
    //}

    // The priv.D must not be zero or negative.
    if priv.D.Sign() <= 0 {
            return nil, fmt.Errorf("invalid private key, zero or negative")
    }

    priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(privateKeyBytes)
    if priv.PublicKey.X == nil {
            return nil, errors.New("invalid private key")
    }
    return priv, nil
}

func NewPrivateKeyByHex(privateKeyHex string) (*ecdsa.PrivateKey, error) {
    privateKeyBytes := HexString2Bytes(privateKeyHex)
    return NewPrivateKey(privateKeyBytes)
}

// func decodeHex(s string) []byte {
//     b, err := hex.DecodeString(s)
//     if err != nil {
//         panic(err)
//     }

//     return b
// }

func FactHash(facts Facts) []byte {
    underlyingHash := sha3.NewLegacyKeccak256()
    underlyingHash.Write([]byte(facts.underlyingString))
    fmt.Println("underlyingHash",  hex.EncodeToString(underlyingHash.Sum(nil)))

    hash := sha3.NewLegacyKeccak256()
    hash.Write(underlyingHash.Sum(nil))
    hash.Write(HexString2Bytes(
        "003a4fc880" + // uint40
        "000e10" + // uint24
        "05" + // uint8
        "00" + // uint8
        "12" + // uint8
        "02" + // int8
        ""))
    return hash.Sum(nil)
}
