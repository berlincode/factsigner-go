package main

import (
    "github.com/berlincode/factsigner-go/factsigner"
    "fmt"
    "encoding/hex"
)

func main() {

    //expirationDatetime := uint64(time.Now().Unix() + 2*3600)
    expirationDatetime := uint64(1580930067+10*3600) // TODO
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
        BaseUnitExp: 0x12, // TODO baseUnitExp integer calculcation
        Ndigit: 0x02};

    factHash := factsigner.FactHash(facts)
    fmt.Println("factHash", hex.EncodeToString(factHash[:]))

    // create
    // https://berlincode.github.io/digioptions-contracts-web-examples/market_create.html#?
    //     settlementDatetime=1572901200&
    //     baseUnitExp=18&
    //     objectionPeriod=3600&
    //     ndigit=0&
    //     underlyingString=US2605661048&
    //     signatureFactHash=%7B%0A++%22r%22%3A+%220x7caf800c43d461bffa6d22bfa2e86fcbbeacc3f02cec008ca05640d78116f9de%22%2C%0A++%22s%22%3A+%220x2e6a7600d8bb52e3868f3a6df4ee63e957df89e7e170f6f63b354d91ef7ecb3d%22%2C%0A++%22v%22%3A+28%0A%7D&
    //     signerAddr=0x6b608020f7a66c727154ed65208e40f9e105f6b8

    signatureCreate := factsigner.Sign(factHash, privateKey)

    fmt.Println("Signature market create")
    fmt.Println("R", hex.EncodeToString(signatureCreate.R[:]))
    fmt.Println("S", hex.EncodeToString(signatureCreate.S[:]))
    fmt.Println("V", signatureCreate.V)

    // https://berlincode.github.io/digioptions-contracts-web-examples/market_create.html#?
    //     signatureFinal=%7B%0A++%22r%22%3A+%220x91ecdf95a8b63c12fce30d1b431ae17e0a4ff03f4abe2e9c01c57702ba071d52%22%2C%0A++%22s%22%3A+%220x53c1e0816060faf823402cbc810d380d14e929d76b955cda1173245bad4cf5e2%22%2C%0A++%22v%22%3A+28%0A%7D&
    //     finalValue=0.266&
    //     signerAddr=0x49b6d897575b0769d45eba7e2de60a16de5b8c13

    var value [32]byte // TODO

    settlementData := factsigner.SettlementData{
        FactHash: factHash,
        Value: value,
        SettlementType: 0};

    factsigner.SettlementHash(settlementData)

    signatureSettle := factsigner.Sign(factHash, privateKey)

    fmt.Println("Signature market settle")
    fmt.Println("R", hex.EncodeToString(signatureSettle.R[:]))
    fmt.Println("S", hex.EncodeToString(signatureSettle.S[:]))
    fmt.Println("V", signatureSettle.V)



}
