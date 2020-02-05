// start with: go run example.go
package main

// import "github.com/berlincode/factsigner-go/factsigner"
import "github.com/berlincode/factsigner-go/factsigner"
import "fmt"
import "encoding/hex"

// func checkStrings (explain string, str string, wanted string, t *testing.T){
//     if str != wanted {
//         t.Errorf("Failed compare: %s (is=%q, expected=%q)", explain, str, wanted)
//     }
// }

func main() {

//     var buf []byte

// {
//   "addr": "0x17078c5cC530Be97690a4606129ab65b24f98dC8",
//   "pk": "0x53b63c349b51ce23793f7ace0d116b7cdb5ee83b8667781feae7a98e5d1043ec",
//   "mnemonic": "carpet sail clarify tragic analyst bone pole connect blue casual various walk"
// }

//     privateKey, err := NewPrivateKeyByHex("53b63c349b51ce23793f7ace0d116b7cdb5ee83b8667781feae7a98e5d1043ec")

    privateKey, err := factsigner.NewPrivateKeyByHex("348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709")
    if err != nil {
            panic(err)
    }

    facts := factsigner.Facts{
        UnderlyingString: "BTC/USDT",
        ExpirationDatetime: 0x3a4fc880,
        ObjectionPeriod: 0x000e10,
        Config: 0x05,
        MarketCategory: 0x00, // TODO enum
        BaseUnitExp: 0x12, // TODO baseUnitExp integger calculcation
        Ndigit: 0x02};

    hash := factsigner.FactHash(facts)

//     checkStrings ("factHash", hex.EncodeToString(hash), "5231a3f9078d41055464a715da1116e394ef5a63496a5e840768875a731f635b", t)

    signature := factsigner.Sign(hash, privateKey)

//     checkStrings ("signature.R", hex.EncodeToString(signature.R[:]), "8e5fe9f3ab83923071809a265de063e1adb2862b57b1d2a81da669792036be3f", t)
//     checkStrings ("signature.S", hex.EncodeToString(signature.S[:]), "381b0a6c319533c641c27bb702de6205a4d0267af738979771a87030b3e87e3f", t)
//     checkStrings ("signature.V", fmt.Sprintf("%x", signature.V), "1c", t)

    // TODO test signature

    fmt.Println("factHash", hex.EncodeToString(hash))
    fmt.Println("R", hex.EncodeToString(signature.R[:]))
    fmt.Println("S", hex.EncodeToString(signature.S[:]))
    fmt.Println("V", signature.V)

    fmt.Println("ok")
}
