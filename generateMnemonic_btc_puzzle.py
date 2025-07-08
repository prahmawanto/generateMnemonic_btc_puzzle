import os
import time
import random
import hashlib
import ecdsa
import base58
from mnemonic import Mnemonic

# Generate a random passphrase using BIP39 standard
def generate_passphrase():
    mnemo = Mnemonic("english")
    words = mnemo.generate(strength=256)
    return words

# Convert passphrase to private key hex
def passphrase_to_private_key(passphrase):
    seed = Mnemonic.to_seed(passphrase)
    private_key = hashlib.sha256(seed).hexdigest()
    return private_key

# Convert private key to public key
def private_key_to_public_key(private_key_hex, compressed=True):
    private_key_bytes = bytes.fromhex(private_key_hex)
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()

    if compressed:
        public_key = b'\x02' + vk.to_string()[:32] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[:32]
    else:
        public_key = b'\x04' + vk.to_string()

    return public_key

# Convert public key to Bitcoin address
def public_key_to_p2pkh_address(public_key):
    sha256_bpk = hashlib.sha256(public_key).digest()
    ripemd160_bpk = hashlib.new('ripemd160', sha256_bpk).digest()
    pre_address = b'\x00' + ripemd160_bpk
    checksum = hashlib.sha256(hashlib.sha256(pre_address).digest()).digest()[:4]
    binary_address = pre_address + checksum
    address = base58.b58encode(binary_address)
    return address.decode()

def main():
    target_addresses = {
"1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
"1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR",
"12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4",
"1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv",
"1DJh2eHFYQfACPmrvpyWc8MSTYKh7w9eRF",
"1Bxk4CQdqL9p22JEtDfdXMsng1XacifUtE",
"15qF6X51huDjqTmF9BJgxXdt1xcj46Jmhb",
"1ARk8HWJMn8js8tQmGUJeQHjSE7KRkn2t8",
"15qsCm78whspNQFydGJQk5rexzxTQopnHZ",
"13zYrYhhJxp6Ui1VV7pqa5WDhNWM45ARAC",
"14MdEb4eFcT3MVG5sPFG4jGLuHJSnt1Dk2",
"1CMq3SvFcVEcpLMuuH8PUcNiqsK1oicG2D",
"1K3x5L6G57Y494fDqBfrojD28UJv4s5JcK",
"1PxH3K1Shdjb7gSEoTX7UPDZ6SH4qGPrvq",
"16AbnZjZZipwHMkYKBSfswGWKDmXHjEpSf",
"19QciEHbGVNY4hrhfKXmcBBCrJSBZ6TaVt",
"1EzVHtmbN4fs4MiNk3ppEnKKhsmXYJ4s74",
"1AE8NzzgKE7Yhz7BWtAcAAxiFMbPo82NB5",
"17Q7tuG2JwFFU9rXVj3uZqRtioH3mx2Jad",
"1K6xGMUbs6ZTXBnhw1pippqwK6wjBWtNpL",
"15ANYzzCp5BFHcCnVFzXqyibpzgPLWaD8b",
"18ywPwj39nGjqBrQJSzZVq2izR12MDpDr8",
"1CaBVPrwUxbQYYswu32w7Mj4HR4maNoJSX",
"1JWnE6p6UN7ZJBN7TtcbNDoRcjFtuDWoNL",
"1CKCVdbDJasYmhswB6HKZHEAnNaDpK7W4n",
"1PXv28YxmYMaB8zxrKeZBW8dt2HK7RkRPX",
"1AcAmB6jmtU6AiEcXkmiNE9TNVPsj9DULf",
"1EQJvpsmhazYCcKX5Au6AZmZKRnzarMVZu",
"18KsfuHuzQaBTNLASyj15hy4LuqPUo1FNB",
"15EJFC5ZTs9nhsdvSUeBXjLAuYq3SWaxTc",
"1HB1iKUqeffnVsvQsbpC6dNi1XKbyNuqao",
"1GvgAXVCbA8FBjXfWiAms4ytFeJcKsoyhL",
"1824ZJQ7nKJ9QFTRBqn7z7dHV5EGpzUpH3",
"18A7NA9FTsnJxWgkoFfPAFbQzuQxpRtCos",
"1NeGn21dUDDeqFQ63xb2SpgUuXuBLA4WT4",
"174SNxfqpdMGYy5YQcfLbSTK3MRNZEePoy",
"1MnJ6hdhvK37VLmqcdEwqC3iFxyWH2PHUV",
"1KNRfGWw7Q9Rmwsc6NT5zsdvEb9M2Wkj5Z",
"1PJZPzvGX19a7twf5HyD2VvNiPdHLzm9F6",
"1GuBBhf61rnvRe4K8zu8vdQB3kHzwFqSy7",
"1GDSuiThEV64c166LUFC9uDcVdGjqkxKyh",
"1Me3ASYt5JCTAK2XaC32RMeH34PdprrfDx",
"1CdufMQL892A69KXgv6UNBD17ywWqYpKut",
"1BkkGsX9ZM6iwL3zbqs7HWBV7SvosR6m8N",
"1AWCLZAjKbV1P7AHvaPNCKiB7ZWVDMxFiz",
"1G6EFyBRU86sThN3SSt3GrHu1sA7w7nzi4",
"1MZ2L1gFrCtkkn6DnTT2e4PFUTHw9gNwaj",
"1Hz3uv3nNZzBVMXLGadCucgjiCs5W9vaGz",
"16zRPnT8znwq42q7XeMkZUhb1bKqgRogyy",
"1KrU4dHE5WrW8rhWDsTRjR21r8t3dsrS3R",
"17uDfp5r4n441xkgLFmhNoSW1KWp6xVLD",
"13A3JrvXmvg5w9XGvyyR4JEJqiLz8ZySY3",
"16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v",
"1UDHPdovvR985NrWSkdWQDEQ1xuRiTALq",
"15nf31J46iLuK1ZkTnqHo7WgN5cARFK3RA",
"1Ab4vzG6wEQBDNQM1B2bvUz4fqXXdFk2WT",
"1Fz63c775VV9fNyj25d9Xfw3YHE6sKCxbt",
"1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo",
"1CD91Vm97mLQvXhrnoMChhJx4TP9MaQkJo",
"15MnK2jXPqTMURX4xC3h4mAZxyCcaWWEDD",
"13N66gCzWWHEZBxhVxG18P8wyjEWF9Yoi1",
"1NevxKDYuDcCh1ZMMi6ftmWwGrZKC6j7Ux",
"19GpszRNUej5yYqxXoLnbZWKew3KdVLkXg",
"1M7ipcdYHey2Y5RZM34MBbpugghmjaV89P",
"18aNhurEAJsw6BAgtANpexk5ob1aGTwSeL",
"1FwZXt6EpRT7Fkndzv6K4b4DFoT4trbMrV",
"1CXvTzR6qv8wJ7eprzUKeWxyGcHwDYP1i2",
"1MUJSJYtGPVGkBCTqGspnxyHahpt5Te8jy",
"13Q84TNNvgcL3HJiqQPvyBb9m4hxjS3jkV",
"1LuUHyrQr8PKSvbcY1v1PiuGuqFjWpDumN",
"18192XpzzdDi2K11QVHR7td2HcPS6Qs5vg",
"1NgVmsCCJaKLzGyKLFJfVequnFW9ZvnMLN",
"1AoeP37TmHdFh8uN72fu9AqgtLrUwcv2wJ",
"1FTpAbQa4h8trvhQXjXnmNhqdiGBd1oraE",
"14JHoRAdmJg3XR4RjMDh6Wed6ft6hzbQe9",
"19z6waranEf8CcP8FqNgdwUe1QRxvUNKBG",
"14u4nA5sugaswb6SZgn5av2vuChdMnD9E5",
"1NBC8uXJy1GiJ6drkiZa1WuKn51ps7EPTv"
    }

    while True:
        passphrase = generate_passphrase()
        print(f"Generated Passphrase: {passphrase}")

        private_key_hex = passphrase_to_private_key(passphrase)
        print(f"Private Key (Hex): {private_key_hex}")

        public_key_compressed = private_key_to_public_key(private_key_hex, compressed=True)
        public_key_uncompressed = private_key_to_public_key(private_key_hex, compressed=False)

        address_compressed = public_key_to_p2pkh_address(public_key_compressed)
        address_uncompressed = public_key_to_p2pkh_address(public_key_uncompressed)

        print(f"Compressed Bitcoin Address: {address_compressed}")
        print(f"Uncompressed Bitcoin Address: {address_uncompressed}")
        print("-" * 60)

        if address_compressed in target_addresses or address_uncompressed in target_addresses:
            result = (f"Private Key: {private_key_hex}\n"
                      f"Compressed Address: {address_compressed}\n"
                      f"Uncompressed Address: {address_uncompressed}\n"
                      f"Passphrase: {passphrase}\n")

            print(f"\nAlamat target ditemukan!\n{result}")
            
            with open("generate1007_1.txt", "w") as f:
                f.write(result)

            if os.name == 'nt':  # If the OS is Windows
                os.system(f"notepad.exe generate1007_1.txt")
            break

if __name__ == "__main__":
    main()
