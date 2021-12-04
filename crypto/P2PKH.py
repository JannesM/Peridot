import random
import ecdsa
from ecdsa.errors import *
from Crypto.Hash import RIPEMD160, SHA256
import base58


def generate_keys():
    """Function to generate an elliptic curve keypair.

    Returns:
        sk (hex): ECDSA private key
        pk (hex): ECDSA public key
        address (decoded): nested address
    """

    private_key = random.getrandbits(256).to_bytes(32, byteorder="little", signed=False)
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()

    x_cor = bytes.fromhex(verifying_key.to_string().hex())[:32]
    y_cor = bytes.fromhex(verifying_key.to_string().hex())[32:]

    if int.from_bytes(y_cor, byteorder="big", signed=True) % 2 == 0:
        public_key = bytes.fromhex(f'02{x_cor.hex()}')
    else:
        public_key = bytes.fromhex(f'03{x_cor.hex()}')

    sha256_key = SHA256.new(public_key)
    ripemd160_key = RIPEMD160.new(sha256_key.digest())

    public_key_hash = ripemd160_key.digest()

    P2PKH_V0 = bytes.fromhex(f'0014{public_key_hash.hex()}')

    sha256_P2WPKH_V0 = SHA256.new(P2PKH_V0)
    ripemd160_P2WPKH_V0 = RIPEMD160.new(sha256_P2WPKH_V0.digest())

    script_hash = ripemd160_P2WPKH_V0.digest()
    flagged_script_hash = bytes.fromhex(f'05{script_hash.hex()}')

    checksum = SHA256.new(SHA256.new(flagged_script_hash).digest()).digest()[:4]

    bin_addr = flagged_script_hash + checksum
    nested_address = base58.b58encode(bin_addr)

    # print("Private key    :", private_key.hex())
    # print("Public key     :", public_key.hex())
    # print("Verify key     :", verifying_key.to_string().hex())
    # print("Nested address :", nested_address.decode())

    return private_key.hex(), public_key.hex(), nested_address.decode()


def sign(sk: str, hash: str):
    """Function to sign a hash (str) with an elliptic curve private key

    Args:
        sk (hex): ECDSA private key
        hash (hex): hash to sign

    Returns:
        signature (hex): the corrsponding ECDSA signature
    """

    try:
        signing_key = ecdsa.SigningKey.from_string(bytes.fromhex(sk), curve=ecdsa.SECP256k1)
        signature = signing_key.sign_deterministic(bytes.fromhex(hash))

        return signature.hex()

    except MalformedPointError:
        return None


def verify_sig(pk: str, hash: str, sig: str):
    """Function to verify an elliptic curve signature

    Args:
        pk (hex): ECDSA public key
        hash (hex): previous signed hash
        sig (hex): ECDSA signature

    Returns:
        falg (boolean): result of the verification
    """

    try:
        verifying_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(pk), curve=ecdsa.SECP256k1)
        return verifying_key.verify(bytes.fromhex(sig), bytes.fromhex(hash))

    except (ecdsa.util.MalformedSignature, ecdsa.keys.BadSignatureError):
        return False


def pk_to_address(pk: str):
    """Function to translate a ECDSA public key to a nested address

    Args:
        pk (hex): ECDSA public key

    Returns:
        nested addres (decoded): the corresponding address
    """

    sha256_key = SHA256.new(bytes.fromhex(pk))
    ripemd160_key = RIPEMD160.new(sha256_key.digest())

    public_key_hash = ripemd160_key.digest()

    P2PKH_V0 = bytes.fromhex(f'0014{public_key_hash.hex()}')

    sha256_P2WPKH_V0 = SHA256.new(P2PKH_V0)
    ripemd160_P2WPKH_V0 = RIPEMD160.new(sha256_P2WPKH_V0.digest())

    script_hash = ripemd160_P2WPKH_V0.digest()
    flagged_script_hash = bytes.fromhex(f'05{script_hash.hex()}')

    checksum = SHA256.new(SHA256.new(flagged_script_hash).digest()).digest()[:4]

    bin_addr = flagged_script_hash + checksum
    return base58.b58encode(bin_addr).decode()


def verify_relation(pk: str, address: str, sig: str, hash: str):
    """Function that verifies the relation between an ECDSA public key, an ECDSA address and an ECDSA signature

    Args:
        pk (str): ECDSA public key
        address (str): nested address
        sig (str): ECDSA signature
        hash (str): previous signed hash

    Returns:
        flag (boolean): returns true if there is a relationship
    """

    if pk_to_address(pk) != address:
        return False

    if not verify_sig(pk, hash, sig):
        return False

    return True



# debugging area ----------------------------------------------------------
# sk, pk, address = generate_keys()
# sk2, pk2, address2 = generate_keys()
# test = SHA256.new(b'test').hexdigest()
#
# print("\n")
# signature = sign(sk, test)
# print("Signature     :", signature)
#
# verify = verify_sig(pk, test, signature)
# print("Verify        :", verify)
#
# verify = verify_sig(pk2, test, signature)
# print("  Tampered    :", verify)
#
# verify = verify_relation(pk, address, signature, test)
# print("Relation      :", verify)
#
# verify = verify_relation(pk, address, f'04{signature}', test)
# print("  Tampered    :", verify)







