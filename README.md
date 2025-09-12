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

Below are two sets of instructions, the first for building from non-FIPS
sources, and the second for building from FIPS-certified sources.  In both
cases, the WolfGuard user tool and script are named `wg-fips` and
`wg-fips-quick`, reflecting their use of FIPS-approved algorithms regardless of
FIPS certification status.  FIPS-certified and non-certified builds of WolfGuard
are fully interoperable with each other, but cannot interoperate with WireGuard.

The `--enable-intelasm` option should only be used with x86 CPU targets, and for
FIPS, only on FIPS sources that support it.  Contact us at <fips@wolfssl.com>
for more info.

Commands prefixed with `$` should be executed by an unprivileged user,
while those with `#` are to be executed with root privileges, but in the same
established working directory context.


### Building and installing non-FIPS `git` sources


(1) Create a top level directory for the sources and populate it:
```
$ mkdir wolf-sources
$ cd wolf-sources
$ git clone https://github.com/wolfssl/wolfssl --branch nightly-snapshot
$ git clone https://github.com/wolfssl/wolfguard
```

(2) Build and install the wolfssl user library:

```
$ cd wolfssl
$ ./autogen.sh
$ ./configure --enable-all-crypto
$ make -j
$ ./wolfcrypt/test/testwolfcrypt
# make install
```

(3) Build and install the `wg-fips` user tool -- note, installation will move existing
WireGuard `wg` and `wg-quick` executables and man pages in the destination directories (if
present) to `wg-wireguard` and `wg-wireguard-quick` respectively, and will
install symbolic links for `wg` and `wg-quick` that point to the WolfGuard versions.
```
$ cd ../wolfguard/user-src
$ make -j
$ ./wg-fips genkey | ./wg-fips pubkey
# make install
```

(4) Build and install the wolfssl kernel module.  Replace `/usr/src/linux` with
the path to your actual target kernel source tree, which must be fully
configured and built, and precisely match the kernel you will boot on your
target system.  The `modprobe` at the end assumes you are targeting the native
running system.
```
$ cd ../../wolfssl
$ ./configure --enable-all-crypto --enable-cryptonly --enable-intelasm \
   --enable-linuxkm --with-linux-source=/usr/src/linux \
   --prefix=$(pwd)/linuxkm/build
$ make -j
# make install
# modprobe libwolfssl
```

(5) Build and install the wolfguard kernel module.  Again, replace
`/usr/src/linux` with the path to your actual target kernel source tree, and
replace `6.16.5-gentoo` with the actual value returned by `uname -r` on the
target system.  And again, the `modprobe` at the end assumes you are targeting
the native running system.
```
$ cd ../wolfguard/kernel-src
$ make -j KERNELDIR=/usr/src/linux KERNELRELEASE=6.16.5-gentoo
# make install
# modprobe wolfguard
```

If all of the above succeeds, then you are now ready to bring up WolfGuard
tunnels.  Existing playbooks and scripting for WireGuard can be used directly,
provided you substitute `/etc/wolfguard` for `/etc/wireguard`, and generate all
keys using the WolfGuard `wg-fips` tool (`wg` will at this point be a link to
`wg-fips`).


### Building and installing FIPS sources

FIPS certified versions of the wolfssl source archive are supplied separately.
Contact <fips@wolfssl.com>.

(1) Create a top level directory for the sources and populate it.  This
procedure assumes a wolfssl archive in `7z` format -- substitute `tar -xf` if the
archive is a `.tar.gz`.  In either case, adjust the `ln -s` recipe to assure
`wolfssl` is a symbolic link to the extracted wolfssl directory.  Also note that
FIPS kernel module archives are distinct from non-kernel archives, though they
are safe to use for building the FIPS user library, as shown below.
```
$ mkdir wolf-sources
$ cd wolf-sources
$ 7z x ~/Downloads/wolfssl-X-fips-linuxvX-kernel.7z
$ ln -s wolfssl-X-fips-linuxvX-kernel wolfssl
$ git clone https://github.com/wolfssl/wolfguard
```

(2) Build and install the wolfssl user library.  The argument to `--enable-fips`
must match the FIPS flavor of the archive.  Currently the most common arguments
are `v5` and `v6`.

```
$ cd wolfssl
$ ./configure --enable-fips=vX --enable-all-crypto
$ make -j
$ ./fips-hash.sh
$ make -j
$ ./wolfcrypt/test/testwolfcrypt
# make install
```

(3) Build and install the `wg-fips` user tool -- note, installation will move existing
WireGuard `wg` and `wg-quick` executables and man pages in the destination directories (if
present) to `wg-wireguard` and `wg-wireguard-quick` respectively, and will
install symbolic links for `wg` and `wg-quick` that point to the WolfGuard versions.
```
$ cd ../wolfguard/user-src
$ make -j
$ ./wg-fips genkey | ./wg-fips pubkey
# make install
```

(4) Build and install the wolfssl kernel module.  Replace `/usr/src/linux` with
the path to your actual target kernel source tree, which must be fully
configured and built, and precisely match the kernel you will boot on your
target system.

This is a two-step process.  First you will build and install the module with an
incorrect integrity hash.  Then you will load it to capture the correct hash
(the instructions assume targeting the native system).  Then you will rebuild
and load the module with the correct hash.
```
$ cd ../../wolfssl
$ ./configure --enable-fips=vX --enable-all-crypto --enable-cryptonly \
   --enable-linuxkm --with-linux-source=/usr/src/linux \
   --prefix=$(pwd)/linuxkm/build
$ make -j
# make install
# modprobe libwolfssl
$ NEWHASH=$(dmesg | awk '{if (match($0, " new hash \"([^\"]+)\" ", hash_a)) { hash = hash_a[1]; }} END {print hash}')
$ sed --in-place=.bak "s/^\".*\";/\"${NEWHASH}\";/" wolfcrypt/src/fips_test.c
$ make -j
# make install
# modprobe libwolfssl
```

(5) Build and install the wolfguard kernel module.  Again, replace
`/usr/src/linux` with the path to your actual target kernel source tree, and
replace `6.16.5-gentoo` with the actual value returned by `uname -r` on the
target system.
```
$ cd ../wolfguard/kernel-src
$ make -j KERNELDIR=/usr/src/linux KERNELRELEASE=6.16.5-gentoo
# make install
# modprobe wolfguard
```

As with the non-FIPS-certified procedure, if all of the above succeeds, then you
are now ready to bring up WolfGuard tunnels.  Existing playbooks and scripting
for WireGuard can be used directly, provided you substitute `/etc/wolfguard` for
`/etc/wireguard`, and generate all keys using the WolfGuard `wg-fips` tool (`wg`
will at this point be a link to `wg-fips`).
