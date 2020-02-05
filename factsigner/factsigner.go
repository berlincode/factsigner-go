// Copyright factsigner.com
//
// This file is part of the factsigner-go library.
//
// Public repository: https://github.com/berlincode/factsigner-go
//
// Code is licensed under the MIT license.

package factsigner

import (
    "fmt"
    "strconv"
    "github.com/ethereum/go-ethereum/crypto"
    "crypto/ecdsa"
    "crypto/elliptic"
    "golang.org/x/crypto/sha3"
    "encoding/hex"
    "strings"
    "errors"
    "math/big"
    "encoding/binary"
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
    UnderlyingString string
    ExpirationDatetime uint64 // uint40
    ObjectionPeriod uint32 // uint24
    Config uint8 // uint8
    MarketCategory uint8 // uint8
    BaseUnitExp uint8 // uint8
    Ndigit uint8 // uint8
}

type SettlementData struct {
    FactHash [32]byte // bytes32
    Value [32]byte // int256
    SettlementType uint16
}

func Sign(message [32]byte, privkey *ecdsa.PrivateKey) Signature {

    validationMsg := "\x19Factsigner Signed Message:\n" + strconv.Itoa(len(message))

    hash := sha3.NewLegacyKeccak256()
    hash.Write([]byte(validationMsg))
    hash.Write(message[:])
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

func Keccak256(data ...[]byte) []byte {
    d := sha3.NewLegacyKeccak256()
    for _, b := range data {
        d.Write(b)
    }
    return d.Sum(nil)
}

func FromECDSAPub(pub *ecdsa.PublicKey) []byte {
    if pub == nil || pub.X == nil || pub.Y == nil {
        return nil
    }
    return elliptic.Marshal(crypto.S256(), pub.X, pub.Y)
}

func PubkeyToAddress(p ecdsa.PublicKey) []byte {
    pubBytes := FromECDSAPub(&p)
    return Keccak256(pubBytes[1:])[12:]
}

func uint64ToBytes(num uint64) []byte {
    bs := make([]byte, 8)
    binary.BigEndian.PutUint64(bs, num)
    return bs
}

func uint32ToBytes(num uint32) []byte {
    bs := make([]byte, 4)
    binary.BigEndian.PutUint32(bs, num)
    return bs
}

func uint16ToBytes(num uint16) []byte {
    bs := make([]byte, 2)
    binary.BigEndian.PutUint16(bs, num)
    return bs
}

func uint8ToBytes(num uint8) []byte {
    return []byte([]uint8{num,})
}

func FactHash(facts Facts) [32]byte {
    underlyingHash := sha3.NewLegacyKeccak256()
    underlyingHash.Write([]byte(facts.UnderlyingString))

    hash := sha3.NewLegacyKeccak256()

    hash.Write(underlyingHash.Sum(nil))
    hash.Write(uint64ToBytes(facts.ExpirationDatetime)[3:8]) // uint40 (take lower 5 bytes)
    hash.Write(uint32ToBytes(facts.ObjectionPeriod)[1:4]) // uint24 (take lower 3 bytes)
    hash.Write(uint8ToBytes(facts.Config)) // uint8
    hash.Write(uint8ToBytes(facts.MarketCategory)) // uint8
    hash.Write(uint8ToBytes(facts.BaseUnitExp)) // uint8
    hash.Write(uint8ToBytes(facts.Ndigit)) // uint8

    var factHash [32]byte
    copy(factHash[:], hash.Sum(nil))

    return factHash
}

func SettlementHash(settlementData SettlementData) [32]byte {
    hash := sha3.NewLegacyKeccak256()

    hash.Write(settlementData.FactHash[:]) // bytes32
    hash.Write(settlementData.Value[:]) // int256
    hash.Write(uint16ToBytes(settlementData.SettlementType)) // uint16

    var settlementHash [32]byte
    copy(settlementHash[:], hash.Sum(nil))

    return settlementHash
}
