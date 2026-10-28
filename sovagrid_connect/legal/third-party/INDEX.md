# Third-party licenses shipped with SovaGrid Connect

Select a file in this window or run `SovaGrid-Connect-CLI third-party-licenses --list`.
All texts below are available offline in this installation. Their licenses
remain the licenses of their respective authors; the SovaGrid AGPL license
applies to SovaGrid's own code.

| Platform | Bundled component | Local license files | Upstream |
| --- | --- | --- | --- |
| Linux | CPython 3.12.3 | `CPython-3.12.3-LICENSE`, `CPython-3.12.3-Doc-license.rst` | https://github.com/python/cpython/tree/v3.12.3 |
| Windows, macOS | CPython 3.13.16 | `CPython-3.13.16-LICENSE`, `CPython-3.13.16-Doc-license.rst` | https://github.com/python/cpython/tree/v3.13.16 |
| Linux | Tcl/Tk 8.6.14 | `tcl-8.6.14-license.terms`, `tk-8.6.14-license.terms` | https://github.com/tcltk |
| Windows | Tcl/Tk 8.6.15 | `tcl-8.6.15-license.terms`, `tk-8.6.15-license.terms` | https://github.com/tcltk |
| macOS | Tcl/Tk 8.6.18 | `tcl-8.6.18-license.terms`, `tk-8.6.18-license.terms` | https://github.com/tcltk |
| Linux | OpenSSL 3.0.13 | `OpenSSL-3.0.13-LICENSE.txt` | https://github.com/openssl/openssl/tree/openssl-3.0.13 |
| Windows, macOS | OpenSSL 3.5.9 | `OpenSSL-3.5.9-LICENSE.txt` | https://github.com/openssl/openssl/tree/openssl-3.5.9 |
| Windows | libffi 3.4.4 | `libffi-3.4.4-LICENSE` | https://github.com/libffi/libffi/tree/v3.4.4 |
| Windows | zlib 1.3.1 | `zlib-1.3.1-LICENSE` | https://github.com/madler/zlib/tree/v1.3.1 |
| All | PyInstaller bootloader 6.22.3 | `PyInstaller-6.22.3-COPYING.txt` | https://github.com/pyinstaller/pyinstaller/tree/v6.22.3 |

CPython's `Doc-license.rst` includes notices for software incorporated into
Python, including expat, libffi, OpenSSL and zlib. The PyInstaller license
contains the special exception for frozen applications.

Linux archives also contain an `ubuntu/` folder generated from the exact
Ubuntu packages installed on the CI build host. Its `MANIFEST.json` maps each
bundled native library to a package, package version, copied copyright file,
and any referenced common license text. Windows archives contain
`windows-runtime.json` recording the provenance of their Microsoft C runtime
DLL. These platform records are generated anew for each binary build.
The generated `runtime.json` records the Python, Tcl, OpenSSL, zlib and
PyInstaller versions and SHA-256 of every static notice. Packaging refuses
an unaudited runtime version rather than silently using another version's
license text.
