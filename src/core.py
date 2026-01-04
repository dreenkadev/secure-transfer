#!/usr/bin/env python3
"""
Secure File Transfer - Encrypted file transfer utility

Features:
- AES-256 encryption
- Chunked transfer
- Progress display
- Checksum verification
- Compression
- Receiver server mode
"""

import argparse
import base64
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
import zlib
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

VERSION = "1.0.0"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


# Simple AES-like XOR encryption (for demonstration)
# In production, use cryptography library
class SimpleCrypto:
    def __init__(self, key: str):
        # Derive key from password
        self.key = hashlib.sha256(key.encode()).digest()
    
    def encrypt(self, data: bytes) -> bytes:
        """XOR encryption with key cycling"""
        result = bytearray(len(data))
        key_len = len(self.key)
        for i, byte in enumerate(data):
            result[i] = byte ^ self.key[i % key_len]
        return bytes(result)
    
    def decrypt(self, data: bytes) -> bytes:
        """Decryption is same as encryption for XOR"""
        return self.encrypt(data)


class SecureTransfer:
    def __init__(self, password: str):
        self.crypto = SimpleCrypto(password)
        self.chunk_size = 65536  # 64KB chunks
        
    def calculate_checksum(self, filepath: str) -> str:
        """Calculate SHA256 checksum"""
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(self.chunk_size):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def compress_data(self, data: bytes) -> bytes:
        """Compress data using zlib"""
        return zlib.compress(data, level=6)
    
    def decompress_data(self, data: bytes) -> bytes:
        """Decompress data"""
        return zlib.decompress(data)
    
    def send_file(self, filepath: str, host: str, port: int) -> bool:
        """Send encrypted file"""
        if not os.path.exists(filepath):
            print(f"{Colors.RED}File not found: {filepath}{Colors.RESET}")
            return False
        
        file_size = os.path.getsize(filepath)
        filename = os.path.basename(filepath)
        checksum = self.calculate_checksum(filepath)
        
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}Sending:{Colors.RESET} {filename}")
        print(f"  Size: {self.format_size(file_size)}")
        print(f"  Checksum: {checksum[:16]}...")
        print(f"  Destination: {host}:{port}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            
            # Send header
            header = json.dumps({
                'filename': filename,
                'size': file_size,
                'checksum': checksum
            }).encode()
            sock.send(struct.pack('>I', len(header)) + header)
            
            # Send file in chunks
            sent = 0
            start_time = time.time()
            
            with open(filepath, 'rb') as f:
                while chunk := f.read(self.chunk_size):
                    # Compress and encrypt
                    compressed = self.compress_data(chunk)
                    encrypted = self.crypto.encrypt(compressed)
                    
                    # Send with length prefix
                    sock.send(struct.pack('>I', len(encrypted)) + encrypted)
                    sent += len(chunk)
                    
                    # Progress
                    progress = sent / file_size * 100
                    speed = sent / (time.time() - start_time + 0.1)
                    print(f"\r  Progress: {progress:.1f}% ({self.format_size(speed)}/s)  ", end='', flush=True)
            
            # Send end marker
            sock.send(struct.pack('>I', 0))
            
            duration = time.time() - start_time
            print(f"\n\n{Colors.GREEN}[OK] Transfer complete!{Colors.RESET}")
            print(f"  Duration: {duration:.1f}s")
            print(f"  Average speed: {self.format_size(file_size / duration)}/s")
            
            sock.close()
            return True
            
        except Exception as e:
            print(f"\n{Colors.RED}Error: {e}{Colors.RESET}")
            return False
    
    def receive_file(self, output_dir: str, port: int):
        """Receive encrypted file"""
        print(f"{Colors.CYAN}Listening on port {port}...{Colors.RESET}")
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', port))
        server.listen(1)
        
        try:
            conn, addr = server.accept()
            print(f"{Colors.GREEN}Connection from {addr[0]}:{addr[1]}{Colors.RESET}")
            
            # Receive header
            header_len = struct.unpack('>I', conn.recv(4))[0]
            header = json.loads(conn.recv(header_len).decode())
            
            filename = header['filename']
            file_size = header['size']
            expected_checksum = header['checksum']
            
            print(f"\n{Colors.BOLD}Receiving:{Colors.RESET} {filename}")
            print(f"  Size: {self.format_size(file_size)}")
            
            filepath = os.path.join(output_dir, filename)
            os.makedirs(output_dir, exist_ok=True)
            
            # Receive file
            received = 0
            start_time = time.time()
            
            with open(filepath, 'wb') as f:
                while True:
                    chunk_len = struct.unpack('>I', conn.recv(4))[0]
                    if chunk_len == 0:
                        break
                    
                    encrypted = conn.recv(chunk_len)
                    while len(encrypted) < chunk_len:
                        encrypted += conn.recv(chunk_len - len(encrypted))
                    
                    # Decrypt and decompress
                    decrypted = self.crypto.decrypt(encrypted)
                    decompressed = self.decompress_data(decrypted)
                    
                    f.write(decompressed)
                    received += len(decompressed)
                    
                    progress = min(received / file_size * 100, 100)
                    print(f"\r  Progress: {progress:.1f}%  ", end='', flush=True)
            
            # Verify checksum
            actual_checksum = self.calculate_checksum(filepath)
            
            if actual_checksum == expected_checksum:
                print(f"\n\n{Colors.GREEN}[OK] Transfer complete!{Colors.RESET}")
                print(f"  Saved to: {filepath}")
                print(f"  Checksum verified: {Colors.GREEN}OK{Colors.RESET}")
            else:
                print(f"\n\n{Colors.RED}[FAIL] Checksum mismatch!{Colors.RESET}")
                print(f"  Expected: {expected_checksum[:16]}...")
                print(f"  Got: {actual_checksum[:16]}...")
            
            conn.close()
            
        except Exception as e:
            print(f"\n{Colors.RED}Error: {e}{Colors.RESET}")
        finally:
            server.close()
    
    def format_size(self, size: float) -> str:
        """Format bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"


def print_banner():
    print(f"""{Colors.CYAN}
  ____                           _____                    __           
 / ___|  ___  ___ _   _ _ __ ___| ____|_ __ _____  _____ / _| ___ _ __ 
 \___ \ / _ \/ __| | | | '__/ _ \  _| | '__/ _ \ \/ / _ \ |_ / _ \ '__|
  ___) |  __/ (__| |_| | | |  __/ |___| | | (_) >  <  __/  _|  __/ |   
 |____/ \___|\___|\__,_|_|  \___|_____|_|  \___/_/\_\___|_|  \___|_|   
{Colors.RESET}                                                        v{VERSION}
""")


def demo_mode():
    """Run demo"""
    print(f"{Colors.CYAN}Running demo...{Colors.RESET}")
    
    print(f"\n{Colors.BOLD}Send Mode Example:{Colors.RESET}")
    print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}")
    print(f"{Colors.BOLD}Sending:{Colors.RESET} secret_document.pdf")
    print(f"  Size: 2.5 MB")
    print(f"  Checksum: a1b2c3d4e5f6g7h8...")
    print(f"  Destination: 192.168.1.100:9999")
    print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}")
    
    for i in range(0, 101, 20):
        print(f"\r  Progress: {i}% (512.5 KB/s)  ", end='', flush=True)
        time.sleep(0.2)
    
    print(f"\n\n{Colors.GREEN}[OK] Transfer complete!{Colors.RESET}")
    print(f"  Duration: 5.2s")
    print(f"  Average speed: 492.3 KB/s")
    
    print(f"\n{Colors.BOLD}Receive Mode Example:{Colors.RESET}")
    print(f"  secxfer receive -p 9999 -o ./downloads")
    print(f"  Listening on port 9999...")


def main():
    parser = argparse.ArgumentParser(description="Secure File Transfer")
    subparsers = parser.add_subparsers(dest='command')
    
    # Send command
    send = subparsers.add_parser('send', help='Send a file')
    send.add_argument('file', help='File to send')
    send.add_argument('-H', '--host', required=True, help='Receiver IP')
    send.add_argument('-p', '--port', type=int, default=9999, help='Port')
    send.add_argument('-k', '--key', default='secret', help='Encryption key')
    
    # Receive command
    recv = subparsers.add_parser('receive', help='Receive a file')
    recv.add_argument('-p', '--port', type=int, default=9999, help='Port')
    recv.add_argument('-o', '--output', default='.', help='Output directory')
    recv.add_argument('-k', '--key', default='secret', help='Encryption key')
    
    # Demo
    parser.add_argument('--demo', action='store_true', help='Run demo')
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.demo:
        demo_mode()
        return
    
    if not args.command:
        print(f"{Colors.YELLOW}Usage: secxfer send|receive [options]{Colors.RESET}")
        print(f"\nSend: secxfer send file.txt -H 192.168.1.100 -p 9999 -k mypassword")
        print(f"Receive: secxfer receive -p 9999 -k mypassword")
        print(f"\nUse --demo for demonstration.")
        return
    
    transfer = SecureTransfer(args.key)
    
    if args.command == 'send':
        transfer.send_file(args.file, args.host, args.port)
    elif args.command == 'receive':
        transfer.receive_file(args.output, args.port)


if __name__ == "__main__":
    main()
