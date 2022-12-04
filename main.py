import asyncio
import codecs
import hashlib
import random
import string
import json
import aiohttp as aiohttp
import base58
import ecdsa

REQUEST_BATCH_SIZE = 1000
BTC_IN_SATOSHI = 100_000_000


def generate_private_key():
    private_key_chars = []
    for index in range(64):
        private_key_chars.append(random.choice(string.hexdigits))
    return ''.join(private_key_chars)


def randomly_change_n_chars(word, n):
    length = len(word)
    word = list(word)
    random_indexes = random.sample(range(0, length), n)
    for random_index in random_indexes:
        word[random_index] = random.choice(string.hexdigits)
    return ''.join(word)


def generate_address(private_key):
    private_key_bytes = codecs.decode(private_key, 'hex')
    # Generating a public key in bytes using Secp256k1 & ECDSA (Elliptic Curve Digital Signature Algorithm) library
    public_key_raw = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key

    public_key_bytes = public_key_raw.to_string()
    # Hex encoding the public key from bytes
    public_key_hex = codecs.encode(public_key_bytes, 'hex')
    # Bitcoin public key begins with bytes 0x04 so we have to add the bytes at the start
    public_key = (b'04' + public_key_hex).decode("utf-8")

    # Checking if the last byte is odd or even
    if ord(bytearray.fromhex(public_key[-2:])) % 2 == 0:
        public_key_compressed = '02'
    else:
        public_key_compressed = '03'

    # Add bytes 0x02 to the X of the key if even or 0x03 if odd
    public_key_compressed += public_key[2:66]

    # Converting to bytearray for SHA-256 hashing
    hex_str = bytearray.fromhex(public_key_compressed)
    sha = hashlib.sha256()
    sha.update(hex_str)
    sha.hexdigest()  # .hexdigest() is hex ASCII

    rip = hashlib.new('ripemd160')
    rip.update(sha.digest())
    key_hash = rip.hexdigest()  # Hash160

    modified_key_hash = "00" + key_hash

    sha = hashlib.sha256()
    hex_str = bytearray.fromhex(modified_key_hash)
    sha.update(hex_str)
    sha.hexdigest()

    sha_2 = hashlib.sha256()
    sha_2.update(sha.digest())
    sha_2.hexdigest()

    checksum = sha_2.hexdigest()[:8]

    byte_25_address = modified_key_hash + checksum

    return base58.b58encode(bytes(bytearray.fromhex(byte_25_address))).decode('utf-8')


def generate_wallet(function_generate_private_key) -> tuple:
    private_key = function_generate_private_key()
    return generate_address(private_key), private_key


def find_wallet_private_key(function_generate_private_key, expected_address=None):
    wallets = []

    while True:
        wallet = generate_wallet(function_generate_private_key)

        if wallet[1] == expected_address:
            print(f'Private key for address "{expected_address}" was found: {wallet[0]}')
            exit(0)

        wallets.append(wallet)

        if len(wallets) == REQUEST_BATCH_SIZE:
            asyncio.run(scan_balances(wallets))
            wallets.clear()


async def get(url, session):
    try:
        async with session.get(url=url) as response:
            return await response.read()

    except Exception as e:
        print("Unable to get url {} due to {}.".format(url, e.__class__))


def get_private_key(wallets, address):
    wallet = list(filter(lambda x: x[0] == address, wallets))[0]
    return wallet[1]


async def scan_balances(wallets):
    scanned_wallet_counter = 0

    async with aiohttp.ClientSession() as session:
        wallet_balances = await asyncio.gather(
            *[get(f"https://blockstream.info/api/address/{wallet[0]}", session) for wallet in wallets])

    wallet_balances = list(map(lambda x: json.loads(x), wallet_balances))

    for wallet_balance in wallet_balances:
        scanned_wallet_counter += 1
        address = wallet_balance['address']
        balance = wallet_balance['chain_stats']['funded_txo_sum'] / BTC_IN_SATOSHI
        print(f"[{scanned_wallet_counter}] address: {address}, balance: {balance} BTC")
        if balance > 0.0:
            print(f"Matching private key: {get_private_key(wallets, address)}")
            exit(0)  # wallet found


if __name__ == '__main__':
    # try to find similar address with similar private key and non-zero balance
    # find_wallet_private_key(
    #     lambda: randomly_change_n_chars('AD5E22D3435A443D103BF983077F2756AB7F27974A32A688749E9B50D48C0009', 1),
    # )

    # try to find similar address with similar private key and non-zero balance or until private key is found
    # for given address
    find_wallet_private_key(
        lambda: randomly_change_n_chars('AD5E22D3435A443D103BF983077F2756AB7F27974A32A688749E9B50D48C0009', 2),
        'kCwWrLQNv4JZPUeYeJ1R8RxysY8MAUBn'
    )

    # try to find address with non-zero balance by generating completely random private keys and checking their balances
    # find_wallet_private_key(
    #     lambda: generate_private_key()
    # )
