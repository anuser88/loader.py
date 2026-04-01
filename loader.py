# Hello
# Welcome to loader.py
"""
ANSI Escape Table

Color   Code
Black   x0
Red     x1
Green   x2
Yellow  x3
Blue    x4
Purple  x5
Cyan    x6
White   x7
(x=3 is foreground, x=4 is background)

Style     Code
Reset     0
Bold      1
Dim       2
Italic    3
Underline 4
Reverse   7
Hidden    8
"""
def ansiesc(text,code):return "\x1b["+str(code)+"m"+str(text)+"\x1b[0m"
def info(text):print(ansiesc("[info]: "+str(text),34))
def warn(text):print(ansiesc("[warning]: "+str(text),33))
def nice(text):print(ansiesc("[SUCCESS]: "+str(text),32))
def err(text):print(ansiesc("[error]: "+str(text),31))
def quit(n=0):input(ansiesc("Press enter to close",1));sys.exit(n)
info("Launching loader.py...")

import sys

########## This is the downloader ##########

info("Initializing downloader...")

# Lazy import
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import threading
    import hashlib
    import os
except Exception as e:
    err("Import failed:\n"+str(e))
    quit(1)

try:
    # Retry session
    def create_session():
        session = requests.Session()

        retry = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"]
        )

        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    # Hash file
    def file_hash(path, algo="sha256"):
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    # Single-thread fallback
    def download_single(session, url, path):
        with session.get(url, stream=True) as r:
            r.raise_for_status()

            with open(path, "wb") as f:
                for chunk in r.iter_content(8192):
                    if chunk:
                        f.write(chunk)

    # Multi-thread worker
    def download_range(session, url, start, end, path):
        headers = {"Range": f"bytes={start}-{end}"}

        with session.get(url, headers=headers, stream=True) as r:
            r.raise_for_status()

            with open(path, "r+b") as f:
                f.seek(start)
                for chunk in r.iter_content(8192):
                    if chunk:
                        f.write(chunk)

    # Multi-thread download
    def download_multi(session, url, path, total_size, num_threads=4):
        # create file
        with open(path, "wb") as f:
            f.truncate(total_size)

        part_size = total_size // num_threads
        threads = []

        for i in range(num_threads):
            start = i * part_size
            end = start + part_size - 1 if i < num_threads - 1 else total_size - 1

            t = threading.Thread(
                target=download_range,
                args=(session, url, start, end, path)
            )
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    # Main function
    def smart_download(url, path, expected_hash=None, threads=4):
        session = create_session()

        # HEAD request
        r = session.head(url)
        r.raise_for_status()

        total_size = int(r.headers.get("content-length") or 0)
        accept_ranges = r.headers.get("accept-ranges")

        info(f"Size: {total_size} bytes")
        info(f"Range support: {accept_ranges}")

        try:
            if total_size > 0 and accept_ranges == "bytes":
                info("Using multithread")
                download_multi(session, url, path, total_size, threads)
            else:
                warn("No multithread download, fallback to single thread")
                download_single(session, url, path)
        except Exception as e:
            err(f"Multithread failed:\n{e}")
            info("Retry single thread fallback")
            download_single(session, url, path)

        # Checksum
        info("Calculating hash...")
        h = file_hash(path)

        info(f"SHA256: {h}")

        if expected_hash:
            if h != expected_hash:
                raise ValueError("File mismatch!")
            else:
                info("Checksum OK")

        nice("Download completed successfully!")
        return h

except Exception as e:
    err("Init failed:\n"+str(e))
    quit(1)

nice("Downloader initialized successfully!")

########## This is the encryptor/decryptor ##########

info("Initializing encryptor/decryptor...")

try:
    # Lazy import
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except Exception as e:
    err("Import failed:\n"+str(e))
    quit(1)

CHUNK_SIZE = 64 * 1024  # 64KB

try:
    # Get key
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200000,
        )
        return kdf.derive(password.encode())

    def encrypt_file_stream(in_path, out_path, password):
        salt = os.urandom(16)
        key = derive_key(password, salt)
        nonce = os.urandom(12)

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        encryptor = cipher.encryptor()

        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            # write header
            fout.write(salt + nonce)

            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break

                ct = encryptor.update(chunk)
                if ct:
                    fout.write(ct)

            encryptor.finalize()

            # write tag
            fout.write(encryptor.tag)

    def decrypt_file_stream(in_path, out_path, password):
        with open(in_path, "rb") as fin:
            salt = fin.read(16)
            nonce = fin.read(12)

            key = derive_key(password, salt)

            # read the rest (do NOT flood RAM)
            file_size = os.path.getsize(in_path)
            tag_size = 16

            ciphertext_size = file_size - 16 - 12 - tag_size

            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
            decryptor = cipher.decryptor()

            with open(out_path, "wb") as fout:
                remaining = ciphertext_size

                while remaining > 0:
                    chunk = fin.read(min(CHUNK_SIZE, remaining))
                    remaining -= len(chunk)

                    pt = decryptor.update(chunk)
                    if pt:
                        fout.write(pt)

                # read tag
                tag = fin.read(tag_size)

                # verify tag
                decryptor.finalize_with_tag(tag)

except Exception as e:
    err("Init failed:\n"+str(e))
    quit(1)

nice("Encryptor/decryptor initialized successfully!")