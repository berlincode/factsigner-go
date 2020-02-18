package main

import (
    "github.com/berlincode/factsigner-go/factsigner"
    "fmt"
    "encoding/hex"
    "net/url"
    "strconv"
    "encoding/json"
    "time"
)

const baseUrl = "https://berlincode.github.io/digioptions-contracts-web-examples/market_create.html#"
// const baseUrl = "http://localhost:10002/digioptions-contracts-web-examples/market_create.html#"
// const baseUrl = "http://localhost:8000/market_create.html#"

func main() {

    expirationDatetime := uint64(time.Now().Unix() + 2*3600)
    //expirationDatetime := uint64(1580930067+10*3600) // TODO
    privateKey, err := factsigner.NewPrivateKeyByHex("53b63c349b51ce23793f7ace0d116b7cdb5ee83b8667781feae7a98e5d1043ec")

    if err != nil {
        panic(err)
    }

    facts := factsigner.Facts{
        UnderlyingString: "Test BTC/USDT",
        ExpirationDatetime: expirationDatetime, // TODO
        ObjectionPeriod: 3600,
        Config: 0x05, // TODO
        MarketCategory: 0x00, // TODO enum
        BaseUnitExp: 18, // TODO baseUnitExp integer calculcation
        Ndigit: 0x02};

    factHash := factsigner.FactHash(facts)
    fmt.Println("factHash:", hex.EncodeToString(factHash[:]))
    fmt.Println("")

    // create

    signatureCreate := factsigner.Sign(factHash, privateKey)

    fmt.Println("Signature market create:")
    fmt.Println("R:", hex.EncodeToString(signatureCreate.R[:]))
    fmt.Println("S:", hex.EncodeToString(signatureCreate.S[:]))
    fmt.Println("V:", signatureCreate.V)

    signatureFactHashMap := map[string]string{
        "r": "0x" + hex.EncodeToString(signatureCreate.R[:]),
        "s": "0x" + hex.EncodeToString(signatureCreate.S[:]),
        "v": strconv.FormatUint(uint64(signatureCreate.V), 10)}


    var signatureCreateJsonBytes []byte
    signatureCreateJsonBytes, err2 := json.MarshalIndent(signatureFactHashMap, "", "  ")
    if err2 != nil {
        panic(err2)
    }

    q0 := url.Values{}
    q0.Add("settlementDatetime", strconv.FormatUint(uint64(facts.ExpirationDatetime), 10)) // TODO settlementDatetime vs ExpirationDatetime
    q0.Add("baseUnitExp", strconv.FormatUint(uint64(facts.BaseUnitExp), 10))
    q0.Add("objectionPeriod", strconv.FormatUint(uint64(facts.ObjectionPeriod), 10))
    q0.Add("config", strconv.FormatUint(uint64(facts.Config), 10))
    q0.Add("marketCategory", strconv.FormatUint(uint64(facts.MarketCategory), 10))
    q0.Add("ndigit", strconv.FormatUint(uint64(facts.Ndigit), 10))
    q0.Add("underlyingString", facts.UnderlyingString)
    q0.Add("signatureFactHash", string(signatureCreateJsonBytes))
    q0.Add("signerAddr", "0x" + hex.EncodeToString(factsigner.PubkeyToAddress(privateKey.PublicKey)))

    q0.Add("namedRanges", "[]") // TODO / dummy

    //q0.Add("ethProvider", "ws://localhost:12345") // TODO

    fmt.Println(baseUrl + "?" + q0.Encode())


    // settle

    fmt.Println("");
    fmt.Println("Signature settlement:");

    var value [32]byte // TODO

    settlementData := factsigner.SettlementData{
        FactHash: factHash,
        Value: value,
        SettlementType: 0};

    factsigner.SettlementHash(settlementData)

    // TODO signatureFinal vs signatureSettle
    signatureSettle := factsigner.Sign(factHash, privateKey)

    fmt.Println("R:", hex.EncodeToString(signatureSettle.R[:]))
    fmt.Println("S:", hex.EncodeToString(signatureSettle.S[:]))
    fmt.Println("V:", signatureSettle.V)

    signatureSettleHashMap := map[string]string{
        "r": "0x" + hex.EncodeToString(signatureSettle.R[:]),
        "s": "0x" + hex.EncodeToString(signatureSettle.S[:]),
        "v": strconv.FormatUint(uint64(signatureSettle.V), 10)}


    var signatureSettleJsonBytes []byte
    signatureSettleJsonBytes, err3 := json.MarshalIndent(signatureSettleHashMap, "", "  ")
    if err3 != nil {
        panic(err3)
    }

    q1 := url.Values{}
    q1.Add("signatureFinal", string(signatureSettleJsonBytes))
    q1.Add("finalValue", "1.0")
    q1.Add("signerAddr", "0x" + hex.EncodeToString(factsigner.PubkeyToAddress(privateKey.PublicKey)))

    //q1.Add("ethProvider", "ws://localhost:12345") // TODO

    fmt.Println(baseUrl + "?" + q1.Encode())

}
