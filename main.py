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
SATOSHI_IN_BTC = 100_000_000

scanned_wallet_counter = 0


def generate_random_private_key() -> str:
    private_key_chars = []
    for index in range(64):
        private_key_chars.append(random.choice(string.hexdigits))
    return ''.join(private_key_chars)


def randomly_change_n_chars(word, n) -> str:
    length = len(word)
    word = list(word)
    random_indexes = random.sample(range(0, length), n)
    for random_index in random_indexes:
        word[random_index] = random.choice(string.hexdigits)
    return ''.join(word)


def shift_adjusment(char, shift):
    raw_ascii_code = ord(char) + shift
    if (48 <= raw_ascii_code <= 57) or (65 <= raw_ascii_code <= 70):
        return chr(raw_ascii_code)
    if raw_ascii_code > 70:
        overflow = raw_ascii_code - 71
        return shift_adjusment('0', overflow)
    if raw_ascii_code > 57:
        overflow = raw_ascii_code - 58
        return shift_adjusment('A', overflow)
    raise "INVALID STATE"


def generate_shifted_private_key(word) -> str:
    length = len(word)
    word = list(word)

    shift = random.randint(1, 15)

    for index in range(0, length):
        word[index] = shift_adjusment(word[index], shift)
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


def check_is_expected_address(wallet, expected_address) -> None:
    global scanned_wallet_counter
    scanned_wallet_counter += 1
    print(f'{scanned_wallet_counter}: {{"private_key": "{wallet[1]}", "public_address": "{wallet[0]}"}}')
    if wallet[1] == expected_address:
        print(f'Private key for address "{expected_address}" was found: {wallet[0]}')
        exit(0)


def find_wallet_private_key(function_generate_private_key, expected_address=None) -> None:
    """Try to find private key which matches to the expected_address or have non-zero balance
    Parameters
    ----------
    function_generate_private_key: lambda
        lambda function returning private key
    expected_address : str
        1) address is given - generates private keys until key for given address is found
        2) address is not given - generates private keys until key for address with non-zero balance is found
    """
    wallets = []
    while True:
        wallet = generate_wallet(function_generate_private_key)
        if expected_address is None:
            wallets.append(wallet)
            if len(wallets) == REQUEST_BATCH_SIZE:
                asyncio.run(scan_balances(wallets))
                wallets.clear()
        else:
            check_is_expected_address(wallet, expected_address)


async def get(url, session):
    try:
        async with session.get(url=url) as response:
            return await response.read()

    except Exception as e:
        print("Unable to get url {} due to {}".format(url, e.__class__))


def get_private_key(wallets, address) -> str:
    wallet = list(filter(lambda x: x[0] == address, wallets))[0]
    return wallet[1]


async def scan_balances(wallets) -> None:
    global scanned_wallet_counter
    async with aiohttp.ClientSession() as session:
        responses = await asyncio.gather(
            *[get(f"https://blockstream.info/api/address/{wallet[0]}", session) for wallet in wallets])

    json_responses = list(map(lambda response: json.loads(response), responses))

    for json_response in json_responses:
        scanned_wallet_counter += 1
        address = json_response['address']
        balance_in_satoshi = json_response['chain_stats']['funded_txo_sum']
        print(f'{scanned_wallet_counter}: '
              f'{{"public_address": "{address}", '
              f'"balance": {{"value": "{balance_in_satoshi / SATOSHI_IN_BTC}", "currency": "BTC"}}}}')
        if balance_in_satoshi > 0:
            print(f"Matching private key: {get_private_key(wallets, address)}")
            exit(0)  # wallet found


def main() -> None:
    # https://www.dropbox.com/sh/x7l8hy3ibjsd4h4/AACWUNJnV4vVLr5UzOCBxh34a?dl=0&preview=communication+with+the+Jaxx+Liberty+support+(2).docx
    # https://www.dropbox.com/sh/x7l8hy3ibjsd4h4/AACWUNJnV4vVLr5UzOCBxh34a?dl=0&preview=addresses+and+keys.txt
    # find_wallet_private_key(
    #     lambda: randomly_change_n_chars(
    #         'AD5E22D3435A443D103BF983077F2756AB7F27974A32A688749E9B50D48C0009', random.randint(1, 64)),
    #
    #     # https://live.blockcypher.com/btc/address/14kCwWrLQNv4JZPUeYeJ1R8RxysY8MAUBn/
    #     '14kCwWrLQNv4JZPUeYeJ1R8RxysY8MAUBn'
    # )

    # find_wallet_private_key(
    #     lambda: generate_shifted_private_key(
    #         'AD5E22D3435A443D103BF983077F2756AB7F27974A32A688749E9B50D48C0009'),
    #
    #     # https://live.blockcypher.com/btc/address/14kCwWrLQNv4JZPUeYeJ1R8RxysY8MAUBn/
    #     '14kCwWrLQNv4JZPUeYeJ1R8RxysY8MAUBn'
    # )

    #try to find address with non-zero balance by generating completely random private keys and checking their balances
    find_wallet_private_key(
        lambda: generate_random_private_key()
    )


if __name__ == '__main__':
    main()
