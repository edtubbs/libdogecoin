// Swift example for using libdogecoin
// This demonstrates basic usage of the libdogecoin C library from Swift

import clibdogecoin

print("Libdogecoin Swift Example")
print("========================\n")

// Initialize the elliptic curve context
dogecoin_ecc_start()
defer {
    // Always cleanup when done
    dogecoin_ecc_stop()
}

// Example 1: Generate a new keypair
print("1. Generating a new keypair...")
var privateKey = [CChar](repeating: 0, count: 53)  // WIF format
var address = [CChar](repeating: 0, count: 35)     // P2PKH address

if generatePrivPubKeypair(&privateKey, &address, 0) == 1 {
    print("   Private Key: \(String(cString: privateKey))")
    print("   Address:     \(String(cString: address))\n")
} else {
    print("   ERROR: Failed to generate keypair\n")
}

// Example 2: Validate the keypair
print("2. Validating the generated keypair...")
if verifyPrivPubKeypair(&privateKey, &address, 0) == 1 {
    print("   ✓ Keypair is valid\n")
} else {
    print("   ✗ Keypair validation failed\n")
}

// Example 3: Generate HD master key
print("3. Generating HD master key...")
var hdMaster = [CChar](repeating: 0, count: 112)
if genHDMaster(0, &hdMaster, 112) == 1 {
    let masterKeyStr = String(cString: hdMaster)
    print("   Master Key: \(masterKeyStr.prefix(50))...\n")
} else {
    print("   ERROR: Failed to generate HD master key\n")
}

// Example 4: Derive a child key from the HD master
print("4. Deriving child address from HD master key...")
var derivedAddress = [CChar](repeating: 0, count: 35)
// Derive address at path m/44'/3'/0'/0/0 (first Dogecoin address)
let account: UInt32 = 0
let addressIndex: UInt32 = 0
let isChange: UInt8 = 0  // 0 = receiving address, 1 = change address

if getDerivedHDAddress(&hdMaster, account, isChange, addressIndex, &derivedAddress, 0) == 1 {
    print("   Derived Address: \(String(cString: derivedAddress))\n")
} else {
    print("   ERROR: Failed to derive address\n")
}

// Example 5: Validate a known Dogecoin address
print("5. Validating known addresses...")
let testAddresses = [
    "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L",  // Valid mainnet
    "noxKJyGPugPRN4wqvrwsrtYXuQCk7yQEsy",  // Valid testnet
    "InvalidAddress123"                      // Invalid
]

for addr in testAddresses {
    var addressCopy = Array(addr.utf8CString)
    let isValid = verifyP2pkhAddress(&addressCopy, addr.count)
    let status = isValid == 1 ? "✓ Valid" : "✗ Invalid"
    print("   \(addr): \(status)")
}

print("\n✓ All examples completed successfully!")
