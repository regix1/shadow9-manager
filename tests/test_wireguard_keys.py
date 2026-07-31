"""Tests for WireGuard key generation."""

import base64

import pytest

from shadow9.wireguard.keys import (
    KEY_BYTES,
    KEY_TEXT_LENGTH,
    Keypair,
    derive_public_key,
    generate_keypair,
    generate_private_key,
    is_valid_key,
)


# RFC 7748 section 6.1. Alice's private key and the public key X25519 must produce from it.
# wireguard-tools v1.0.20210914 produces the same answer from the same input, so this vector
# is what stops a change in `cryptography` from silently producing keys `wg` cannot use.
RFC_7748_PRIVATE_HEX = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
RFC_7748_PUBLIC_HEX = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"


def test_rfc_7748_vector() -> None:
    private_key = base64.b64encode(bytes.fromhex(RFC_7748_PRIVATE_HEX)).decode("ascii")

    public_key = derive_public_key(private_key)

    assert base64.b64decode(public_key).hex() == RFC_7748_PUBLIC_HEX


def test_generated_private_key_has_the_shape_wg_expects() -> None:
    private_key = generate_private_key()

    assert len(private_key) == KEY_TEXT_LENGTH
    assert len(base64.b64decode(private_key, validate=True)) == KEY_BYTES


def test_keys_use_the_standard_base64_alphabet() -> None:
    # every other base64 call in this project is urlsafe, which swaps + and / for - and _
    # and produces keys the wg binary rejects
    keys = [generate_private_key() for _ in range(200)]
    keys.extend(derive_public_key(key) for key in list(keys))

    assert not any("-" in key or "_" in key for key in keys)


def test_private_keys_are_stored_clamped() -> None:
    # X25519 clamps the scalar, and `wg genkey` stores the clamped form. Storing an
    # unclamped key would still work but would not round-trip through the wg tools byte
    # for byte, so a config diff would show a change that is not one
    for _ in range(50):
        raw = base64.b64decode(generate_private_key())
        assert raw[0] & 248 == raw[0]
        assert raw[31] & 127 | 64 == raw[31]


def test_derive_public_key_is_deterministic() -> None:
    private_key = generate_private_key()

    assert derive_public_key(private_key) == derive_public_key(private_key)


def test_keypair_public_key_matches_its_private_key() -> None:
    keypair = generate_keypair()

    assert keypair.public_key == derive_public_key(keypair.private_key)


def test_every_keypair_is_different() -> None:
    keypairs = [generate_keypair() for _ in range(100)]

    assert len({keypair.private_key for keypair in keypairs}) == 100
    assert len({keypair.public_key for keypair in keypairs}) == 100


def test_keypair_string_forms_hide_the_private_key() -> None:
    keypair = generate_keypair()

    assert keypair.private_key not in repr(keypair)
    assert keypair.private_key not in str(keypair)
    assert keypair.private_key not in f"{keypair}"
    assert keypair.public_key in repr(keypair)


def test_a_broken_key_error_does_not_repeat_the_key() -> None:
    # this is the path a malformed private key takes, and the message ends up in a log
    secret = "not base64 at all!!"

    with pytest.raises(ValueError) as caught:
        derive_public_key(secret)

    assert secret not in str(caught.value)


def test_derive_public_key_rejects_a_key_of_the_wrong_length() -> None:
    short_key = base64.b64encode(b"\x01" * 16).decode("ascii")

    with pytest.raises(ValueError, match="16 bytes"):
        derive_public_key(short_key)


def test_is_valid_key_accepts_a_generated_key() -> None:
    keypair = generate_keypair()

    assert is_valid_key(keypair.private_key)
    assert is_valid_key(keypair.public_key)


@pytest.mark.parametrize(
    "candidate",
    [
        "",
        "short",
        "!" * KEY_TEXT_LENGTH,
        base64.b64encode(b"\x01" * 16).decode("ascii"),
        base64.b64encode(b"\x01" * 64).decode("ascii"),
        base64.urlsafe_b64encode(b"\xff" * 32).decode("ascii"),
    ],
)
def test_is_valid_key_rejects_anything_else(candidate: str) -> None:
    assert not is_valid_key(candidate)


def test_keypair_fields_are_read_back_unchanged() -> None:
    keypair = Keypair(private_key="private", public_key="public")

    assert keypair.private_key == "private"
    assert keypair.public_key == "public"
