# Cryptopals Solutions

Solutions to the [Cryptopals Crypto Challenges](https://cryptopals.com/), implemented in Python and C.
Currently, this repo contains solutions for the first 2 sets of Cryptopals problems 

## Layout

```
.
├── python-solutions/
│   ├── src/            # One module per challenge: task01.py ... task16.py
│   ├── tests/          # pytest test suite, one file per challenge
│   ├── setup.py
│   └── pytest.ini
└── c-solutions/
    ├── task01.c ... task16.c   # One executable per challenge
    ├── byte_utils.*, crypto_utils.*, file_utils.*  # Shared helper libraries
    └── CMakeLists.txt
```

## Python

Requires Python 3.9+.

```bash
cd python-solutions
pip install -e .[dev]
pytest
```

Individual challenges can also be run directly as a module, e.g. `python -m src.task01` (run from
the `python-solutions` directory).

## C

Requires CMake 3.20+ and OpenSSL.

```bash
cd c-solutions
cmake -B build -S .
cmake --build build
./build/crypto_task01   # replace 01 with the desired challenge number
```

Pass `-DUSE_LIBSODIUM=ON` to `cmake` to link against libsodium where supported.
