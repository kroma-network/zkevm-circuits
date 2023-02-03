package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"main/gethutil"
)

func main() {
	address := common.BytesToAddress([]byte{0xff})
	assembly := gethutil.NewAssembly().MStore(0x40, 0x80).MSize().Stop()

	accounts := map[common.Address]gethutil.Account{address: {Code: assembly.Bytecode()}}
	tx := gethutil.Transaction{To: &address, GasLimit: 21100}

	result, err := gethutil.Trace(gethutil.TraceConfig{Accounts: accounts, Transactions: []gethutil.Transaction{tx},
		Block: gethutil.Block{
			GasLimit: (*hexutil.Big)(new(big.Int).SetInt64(15000000)),
		}})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to trace tx, err: %v\n", err)
	}

	bytes, err := json.MarshalIndent(result[0].StructLogs, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal logs, err: %v\n", err)
	}

	fmt.Fprintln(os.Stdout, string(bytes))
}
