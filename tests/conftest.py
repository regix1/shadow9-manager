"""Settings that apply to the whole test suite."""

import os
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from shadow9.auth import ALLOW_PLAINTEXT_ENV

_CHECKOUT = Path(__file__).resolve().parent.parent

# The suite builds credential stores without a master key on purpose. Most tests only want
# somewhere to put a few users for the length of one test, and generating a key and a salt
# for each of them would buy nothing. An installed copy must never do that, because a store
# with no key writes its users as plain JSON into a file named credentials.enc, so
# AuthManager refuses unless this says otherwise.
#
# Set here rather than in a fixture so it is in place before pytest imports and collects the
# test modules, which is earlier than any fixture can run, and so there is no ordering
# question about which tests are covered. Assigned rather than defaulted, because the suite
# has to behave the same whatever the developer running it happens to have exported.
os.environ[ALLOW_PLAINTEXT_ENV] = "1"

# Point the install root at an empty directory of its own. Shadow9Paths otherwise walks a
# list of standard locations and takes the first one holding a .env or a config directory,
# which on a developer's checkout is the working tree, so the suite would read the
# operator's own master key rather than the one each test set up. Assigned before the test
# modules are imported, because the first Shadow9Paths built in a process is the one every
# later caller is handed.
_TEST_ROOT = Path(tempfile.mkdtemp(prefix="shadow9-tests-", dir=tempfile.gettempdir())).resolve()

# Whatever else goes wrong, the suite must not end up treating part of the checkout as an
# install and filling it with a config directory, a salt and a set of users. Refusing here
# costs one comparison and turns that into a message rather than a mess.
if _TEST_ROOT == _CHECKOUT or _CHECKOUT in _TEST_ROOT.parents:
    raise RuntimeError(f"the tests' install root landed inside the checkout: {_TEST_ROOT}")

os.environ["SHADOW9_HOME"] = str(_TEST_ROOT)


def pytest_sessionfinish() -> None:
    """Take the run's install root away with it, rather than leaving one per run behind."""
    shutil.rmtree(_TEST_ROOT, ignore_errors=True)


@pytest.fixture(autouse=True)
def keep_the_checkouts_env_out() -> Iterator[None]:
    """Keep variables that came from the checkout's own .env out of every test.

    shadow9.cli reads a .env into os.environ as it is imported, starting with the one in the
    current directory, and that import happens while pytest is collecting, which is after
    everything above this has already run. A master key arriving that way beats SHADOW9_HOME
    outright, because load_master_key reads the environment before it looks at any file.

    What that costs is a suite whose answer depends on whose machine it runs on. One store
    opens with the operator's real key and writes ciphertext, the next opens keyless and
    reads the same file as JSON, and five WireGuard tests fail on a checkout that has a .env
    while passing on a clean one.

    SHADOW9_HOME and the plaintext opt-in are the two this suite sets for itself, so they
    stay. Everything else the install would read is put back afterwards.
    """
    kept = {ALLOW_PLAINTEXT_ENV, "SHADOW9_HOME"}
    removed = {
        name: value
        for name, value in os.environ.items()
        if name.startswith("SHADOW9_") and name not in kept
    }

    for name in removed:
        del os.environ[name]

    try:
        yield
    finally:
        os.environ.update(removed)
