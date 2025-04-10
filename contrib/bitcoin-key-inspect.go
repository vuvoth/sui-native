package main

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip39"
)

// mnemonicToBitcoinP2PKH converts a BIP39 mnemonic to a Bitcoin P2PKH address.
// Returns the address and public key as a hex string
func mnemonicToBitcoinP2PKH(mnemonic string, params *chaincfg.Params) (string, string, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "") // "" is the optional password
	if err != nil {
		return "", "", fmt.Errorf("failed to generate seed: %w", err)
	}

	masterKey, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		return "", "", fmt.Errorf("failed to create master key: %w", err)
	}
	derivedKey, err := masterKey.Derive(params.HDCoinType)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive HD key: %w", err)
	}

	pubKey, err := derivedKey.ECPubKey()
	if err != nil {
		return "", "", fmt.Errorf("failed to get public key: %w", err)
	}

	pubKeyBytes := pubKey.SerializeCompressed() // or SerializeUncompressed() if you want uncompressed
	address, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(pubKeyBytes), params)
	if err != nil {
		return "", "", fmt.Errorf("failed to create P2PKH address: %w", err)
	}

	return address.EncodeAddress(), hex.EncodeToString(pubKeyBytes), nil
}

func main() {
	// Example usage: Replace with your mnemonic.  *Never* hardcode a real mnemonic.
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	// accountIndex := 0
	// addressIndex := 0
	params := &chaincfg.MainNetParams

	address, publicKey, err := mnemonicToBitcoinP2PKH(mnemonic, params)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Bitcoin Address:", address)
	fmt.Println("Public Key:", publicKey)
}
