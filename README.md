# Encrypted Diary

A simple C++ program that uses AES encryption to protect diary entries with password protection.

## Features
- AES-256 encryption using OpenSSL
- Password-based key derivation
- Simple command-line interface
- File-based storage

## Requirements
- C++ compiler
- OpenSSL development libraries

## Building the Program
g++ encrypted_diary.cpp -o encrypted_diary -lssl -lcrypto
## Usage
1. Run the program: `./encrypted_diary`
2. Choose to encrypt or decrypt a diary entry
3. Enter the filename and password
4. Follow the prompts to write or read your diary
