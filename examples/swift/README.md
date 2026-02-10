# Swift Examples for libdogecoin

This directory contains Swift examples demonstrating how to use the libdogecoin C library from Swift.

## Prerequisites

- Swift 5.9 or later
- Xcode (for macOS/iOS) or Swift toolchain (for Linux)

## Building and Running

The Swift Package Manager integration is defined in the root `Package.swift` file.

### Option 1: Standalone Example

To run the example as a standalone program, create a new Swift package that depends on libdogecoin:

```bash
# Create a new directory
mkdir MyDogecoinApp
cd MyDogecoinApp

# Create Package.swift
cat > Package.swift << 'EOF'
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MyDogecoinApp",
    dependencies: [
        .package(path: "/path/to/libdogecoin")
    ],
    targets: [
        .executableTarget(
            name: "MyDogecoinApp",
            dependencies: [
                .product(name: "clibdogecoin", package: "libdogecoin")
            ]
        )
    ]
)
EOF

# Copy the example
cp /path/to/libdogecoin/examples/swift/example.swift Sources/MyDogecoinApp/main.swift

# Build and run
swift run
```

### Option 2: Using in an iOS/macOS App

Add libdogecoin as a package dependency in Xcode:

1. Open your Xcode project
2. Go to File → Add Package Dependencies
3. Add the path to your local libdogecoin repository or a GitHub URL
4. Select "clibdogecoin" as the product
5. Import and use:

```swift
import clibdogecoin

class DogecoinWallet {
    init() {
        dogecoin_ecc_start()
    }
    
    deinit {
        dogecoin_ecc_stop()
    }
    
    func generateAddress() -> (privateKey: String, address: String)? {
        var privkey = [CChar](repeating: 0, count: 53)
        var address = [CChar](repeating: 0, count: 35)
        
        guard generatePrivPubKeypair(&privkey, &address, 0) == 1 else {
            return nil
        }
        
        return (
            privateKey: String(cString: privkey),
            address: String(cString: address)
        )
    }
}
```

## What's Included

The libdogecoin Swift package includes:

- ✅ Key generation and management
- ✅ Address generation and validation
- ✅ HD wallet support (BIP32/BIP39/BIP44)
- ✅ Transaction building and signing
- ✅ Cryptographic operations
- ✅ QR code generation

## What's Not Included

The Swift package excludes networking components:

- ❌ SPV node functionality
- ❌ Peer-to-peer networking
- ❌ Block/header synchronization

For networking, use Swift's native APIs:
- URLSession for HTTP/REST
- Network.framework for TCP/UDP
- Third-party libraries like swift-nio

## Examples

### Generate a Keypair

```swift
import clibdogecoin

dogecoin_ecc_start()
defer { dogecoin_ecc_stop() }

var privateKey = [CChar](repeating: 0, count: 53)
var address = [CChar](repeating: 0, count: 35)

if generatePrivPubKeypair(&privateKey, &address, 0) == 1 {
    print("Private Key: \(String(cString: privateKey))")
    print("Address: \(String(cString: address))")
}
```

### Generate HD Wallet

```swift
import clibdogecoin

dogecoin_ecc_start()
defer { dogecoin_ecc_stop() }

var hdMaster = [CChar](repeating: 0, count: 112)
genHDMaster(0, &hdMaster, 112)

var address = [CChar](repeating: 0, count: 35)
getDerivedHDAddress(&hdMaster, 0, 0, 0, &address, 0)

print("First address: \(String(cString: address))")
```

### Validate an Address

```swift
import clibdogecoin

let addr = "DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"
var addressCopy = Array(addr.utf8CString)

let isValid = verifyP2pkhAddress(&addressCopy, addr.count)
print("Valid: \(isValid == 1)")
```

## API Reference

The full C API is available through the `clibdogecoin` module. Key functions include:

- `dogecoin_ecc_start()` / `dogecoin_ecc_stop()` - Initialize/cleanup ECC
- `generatePrivPubKeypair()` - Generate a keypair
- `verifyPrivPubKeypair()` - Verify a keypair
- `verifyP2pkhAddress()` - Validate an address
- `genHDMaster()` - Generate HD master key
- `getDerivedHDAddress()` - Derive child addresses
- `generateRandomEnglishMnemonic()` - Generate BIP39 mnemonic
- `start_transaction()` / `add_utxo()` / `add_output()` - Build transactions

## Platform Notes

### Linux
The package builds successfully on Linux with Swift 5.9+. The required fix for `ssize_t` has been applied.

### macOS
Works natively on macOS 12+ with Xcode 14+.

### iOS
Compatible with iOS 15+. Note that some functionality may require entitlements (e.g., keychain access for secure key storage).

## Support

For issues specific to the Swift integration, please file an issue on the libdogecoin repository.

For general libdogecoin usage questions, see the main [README.md](../../README.md) and [documentation](../../doc/).
