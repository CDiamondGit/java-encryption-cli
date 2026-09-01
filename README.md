# SecureFile

SecureFile is a cross-platform command-line utility for password-based file encryption and decryption, written in Java.

It uses AES-256-GCM for authenticated encryption and PBKDF2-HMAC-SHA256 for password-based key derivation. Files are processed in chunks, allowing large files to be encrypted and decrypted without loading the entire file into memory.

---

## Features

* AES-256-GCM authenticated encryption
* PBKDF2-HMAC-SHA256 key derivation
* 600,000 PBKDF2 iterations
* Random salt and nonce generation
* Hidden password input
* Streaming file processing
* Progress display for encryption and decryption
* Detection of incorrect passwords or corrupted files
* Temporary-file handling during authenticated decryption
* Automatic output filename collision handling
* macOS, Linux, and Windows launchers

---

## Requirements

SecureFile requires:

* Java 25 or newer

---

## Usage

Encrypt a file:

```text
securefile encrypt <file>
```

Decrypt a file:

```text
securefile decrypt <file>
```

For example:

```text
securefile encrypt document.pdf
```

This creates:

```text
document.pdf.sec
```

Decrypt it with:

```text
securefile decrypt document.pdf.sec
```

which restores:

```text
document.pdf
```

Absolute and relative file paths are supported.

---

## Download

Download the appropriate archive from the GitHub Releases page:

* `securefile-macos-linux.zip`
* `securefile-windows.zip`

Extract the archive before using SecureFile.

---

## macOS / Linux

The downloaded archive contains:

```text
securefile
securefile.jar
```

If necessary, make the launcher executable:

```bash
chmod +x securefile
```

Run SecureFile directly from the extracted directory with:

```bash
./securefile encrypt file.txt
```

or:

```bash
./securefile decrypt file.txt.sec
```

### Run SecureFile from anywhere

To run SecureFile anywhere, the `securefile` launcher must be in a directory included in your `PATH`.

On most macOS and Linux systems, `/usr/local/bin` is already included in `PATH`.

Move both the launcher and JAR into `/usr/local/bin`:

```bash
sudo mv securefile securefile.jar /usr/local/bin/
```

The launcher and JAR must remain together.

SecureFile can then be run from any directory.

---

## Windows

The downloaded archive contains:

```text
securefile.bat
securefile.jar
```

### Command Prompt

Run SecureFile directly from the extracted directory with:

```cmd
securefile encrypt file.txt
```

or:

```cmd
securefile decrypt file.txt.sec
```

### PowerShell

Run SecureFile directly from the extracted directory with:

```powershell
.\securefile.bat encrypt file.txt
```

or:

```powershell
.\securefile.bat decrypt file.txt.sec
```

### Run SecureFile from anywhere

To run SecureFile anywhere, the directory containing `securefile.bat` must be included in your `PATH`.

Add the extracted SecureFile directory to your user `PATH`:

1. Search for **Environment Variables** in the Windows Start menu.
2. Open **Edit environment variables for your account**.
3. Select `Path` and click **Edit**.
4. Click **New** and enter the path to the extracted SecureFile directory.
5. Click **OK** to save the changes.

The launcher and JAR must remain together.

SecureFile can then be run from any directory.

---

## Encryption Details

SecureFile uses:

* AES-256-GCM
* 128-bit GCM authentication tags
* PBKDF2-HMAC-SHA256
* 600,000 PBKDF2 iterations
* 256-bit derived keys
* 16-byte random salts
* 12-byte random nonces

Each encrypted file contains:

```text
Magic bytes
Version
Salt
Nonce
Ciphertext
GCM authentication tag
```

Encrypted files use the `.sec` extension.

A new salt and nonce are generated for every encryption operation.

During decryption, output is written to a temporary file until AES-GCM authentication succeeds. If authentication fails, the temporary file is deleted rather than being moved to the final output location.

Passwords are read into mutable character arrays and overwritten after the cryptographic operation completes.