# WolfGuard VPN with FIPS 140-3 cryptography

WolfGuard is the wolfSSL FIPS-compliant refactor of Linux kernel-based
[WireGuard](https://www.wireguard.com/), originally designed and authored by
Jason Donenfeld.  Usage is essentially identical.  There are two principal
components to WolfGuard, the `wolfguard.ko` kernel module and the `wg-fips`
configuration tool.  `wolfguard.ko` depends on the `libwolfssl.ko` kernel
module, and `wg-fips` depends on the `libwolfssl.so` library &mdash; these
dependencies are built from the same
[wolfSSL](https://github.com/wolfssl/wolfssl) source, with kernel
module and user library configuration respectively.  The `wg-fips-quick` script
works exactly like `wg-quick` in WireGuard, but with configuration scripts in
`/etc/wolfguard` containing SECP256R1 public and private keys.

Symbolic links are installed in the installation bin directory from `wg` to
`wg-fips`, and from `wg-quick` to `wg-fips-quick`, for transparent drop-in
replacement of WireGuard.  If WireGuard executables are found during
installation, they are renamed to `wg-wireguard` and `wg-wireguard-quick`, with
`wg-wireguard-quick` modified to call `wg-wireguard`, and with a safety copy
left at `wg-wireguard-quick.unpatched`.

WolfGuard remaps cryptography from WireGuard as follows:

| Algo category | WireGuard          | WolfGuard   |
| :----------- | :--------          | :--------   |
| ECDH         | Curve25519         | SECP256R1   |
| AEAD         | XChaCha20-Poly1305 | AES-256-GCM |
| digest       | Blake2s            | SHA2-256    |
| authenticating digest | Blake2s-HMAC | SHA2-256-HMAC |
| internal hash | SipHash            | SHA2-256    |
| DRBG         | ChaCha20 DRBG      | SHA2-256 Hash-DRBG |

Note that WolfGuard and WireGuard can coexist on the same system, simultaneously
establishing WolfGuard and WireGuard tunnels.

If `libwolfssl.ko` is configured with `--enable-intelasm`, performance of
WolfGuard matches or exceeds that of CPU-accelerated WireGuard, thanks to CPU
acceleration of the AES-256-GCM and SHA2-256 operations.  Without
`--enable-intelasm`, WolfGuard is slightly slower than CPU-accelerated
WireGuard, but is still capable of saturating gigabit ethernet on modern CPUs.

## Building and Installation

Arrange your source tree with this `wolfguard` source archive alongside the
`wolfssl` source archive.  These instructions assume `git` sources with that
layout, and assume an x86 CPU target.  Commands prefixed with `$` should be
executed by an unprivileged user, while those with `#` are to be executed with
root privileges.

From the top of the source hierarchy:

(1) Build and install the wolfssl user library:

```
$ cd wolfssl
$ ./autogen.sh
$ ./configure --enable-all-crypto
$ make -j
$ ./wolfcrypt/test/testwolfcrypt
# make install
```

(2) Build and install the `wg-fips` user tool:
```
$ cd ../wolfguard/user-src
$ make -j
$ ./wg-fips genkey | ./wg-fips pubkey
# make install
```

(3) Build and install the wolfssl kernel module.  Replace `/usr/src/linux` with
the path to your actual target kernel source tree, which must be fully
configured and built, and precisely match the kernel on your target system.
```
$ cd ../../wolfssl
$ ./configure --enable-all-crypto --enable-cryptonly --enable-intelasm \
   --enable-linuxkm --with-linux-source=/usr/src/linux \
   --prefix=$(pwd)/linuxkm/build
$ make -j
# make install
```

(4) Build and install the wolfguard kernel module.  Again, replace
`/usr/src/linux` with the path to your actual target kernel source tree, and
replace `6.16.5-gentoo` with the actual value returned by `uname -r` on the
target system.
```
$ cd ../wolfguard/kernel-src
$ make -j KERNELDIR=/usr/src/linux KERNELRELEASE=6.16.5-gentoo
# make install
```

FIPS certified versions of wolfssl are supplied separately, with additional
instructions.  Contact <fips@wolfssl.com>.
