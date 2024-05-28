
# SafeSerpent
<div align="center">
  <img src="https://github.com/Senal-Punsara/SafeSerpent/blob/main/_internal/logo.png" alt="logo" width="500" height="500">
</div>
Welcome to SafeSerpent! This software is designed to provide a secure and straightforward way to encrypt and decrypt your files. Whether you're looking to protect sensitive information or simply want to ensure your personal data is safe, SafeSerpent offers an easy-to-use solution.

## Features
- **File Encryption:** Securely encrypt your files using AES-GCM-256 algorithm.
- **File Decryption:** Easily decrypt files that were previously encrypted with SafeSerpent.
- **User-Friendly Interface:** Intuitive user interface for seamless operation.
- **Cross-Platform:** Compatible with Windows, macOS, and Linux.(Setup file is only available for Windows. For other platroms please refer **Getting Started** section)
- **Open Source:** Fully open-source and available on GitHub.

## Getting Started

### Setup File
Windows : click [here](https://drive.google.com/file/d/1HdDqxmrsizE6aHMKXw9eka8Z4DyrVbqT/view?usp=sharing) to download

### Prerequisites

To use SafeSerpent without the setup file, you need to have Python 3 installed on your system. You can download it from the [official Python website](https://www.python.org/downloads/).

### Installation

Open the terminal. Clone the repository to your local machine. Then navigate to the SafeSerpent directory.

```bash
git clone https://github.com/Senal-Punsara/SafeSerpent.git
cd SafeSerpent
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```
### Run the Programme

```bash
python SafeSerpent.py 
```
or

```bash
python3 SafeSerpent.py 
```
## Usage
SafeSerpent allows you to encrypt and decrypt files with ease. Below are the instructions for using the application.

### Encrypting a File

<div align="center">
  <img src="https://github.com/Senal-Punsara/SafeSerpent/blob/dev/screenshots/encryption_tab.png" alt="encryption_tab" width="500" height="360">
</div>

1. Navigate to the Encryption Tab: Click on the "Encryption" tab in the application.

2. Select Your File:
- Click the "Browse" button next to the "Your File" field.
- Choose the file you want to encrypt from your file system.
3. Enter Your Key:
- In the "Your Key" field, enter a secure key. This key will be used to encrypt the file. Make sure to remember this key, as you will need it to decrypt the file later.
- You can toggle the visibility of the key by clicking the "Show" button.
4. Encrypt the File:
- Click the "Encrypt" button to start the encryption process.
- A status message will indicate the progress, and a message box will confirm the success once the file is encrypted.
- The encrypted file will be saved with a .enc extension in the same directory as the original file.

### Decrypting a File

<div align="center">
  <img src="https://github.com/Senal-Punsara/SafeSerpent/blob/dev/screenshots/decryption_tab.png" alt="decryption_tab" width="500" height="360">
</div>

1. Navigate to the Decryption Tab: Click on the "Decryption" tab in the application.

2. Select Your Encrypted File:
- Click the "Browse" button next to the "Your File" field.
- Choose the encrypted file (with a .enc extension) you want to decrypt.
3. Enter Your Key:
- In the "Your Key" field, enter the same key you used for encryption.
- You can toggle the visibility of the key by clicking the "Show" button.
4. Decrypt the File:
- Click the "Decrypt" button to start the decryption process.
- A status message will indicate the progress, and a message box will confirm the success once the file is decrypted.
- The decrypted file will be saved in the same directory with "(decrypted)" added to end of its name.

## Contributing

We welcome contributions to SafeSerpent! If you have any ideas, bug reports, or feature requests, please open an issue on GitHub. You can also fork the repository and submit a pull request.
### Steps to Contribute
1. Fork the repository.
2. Create a new branch (git checkout -b feature-branch).
3. Make your changes and commit them (git commit -am 'Add new feature <feature name>').
4. Push to the branch (git push origin feature-branch).
5. Open a pull request.
6. Please adhere to this project's `code of conduct`.

## License

SafeSerpent is licensed under the MIT License. See the [LICENSE](https://github.com/Senal-Punsara/SafeSerpent/blob/dev/LICENSE) file for more details.

This project incorporates with third-party libraries. See the [THIRD_PARTY_LICENSES](https://github.com/Senal-Punsara/SafeSerpent/blob/dev/THIRD_PARTY_LICENSES) file for more details.

## Contact
For any inquiries or support, please send a mail at kksenalpunsara@gmail.com.