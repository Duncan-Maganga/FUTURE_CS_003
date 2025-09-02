# Secure File Sharing System   


**Project:** Secure File Sharing System  
**Tools Used:** Python Flask, Postman, Ngrok,curl  
**Prepared by:** Duncan Maganga  
**Date:** August 23, 2025    


## Executive Summary
This project forcused in desinging and implementing of secure file sharing system, I build a simple and effective platform that allows users to safely upload and download files as security being the primary consideration.
The system is mainly build using Python Flask for the backend and HTML for the frontend. To make sure that confidentiality is maintained to top notch I used AES encryption to all files at rest and during transer. I tested the system with **Postman** and **curl** and validated the system  performance.

## Purpose and Scope  

In today's digital lanscape alot of attacks have recorded and ensuring that we have a realiable mechanisms to exchange data without exposing them to unauthorized peoples, reducing the rate of cyber threats across industries such as healthcare, legal and finance we need a system with ensures confidentiality. The main purpose for this project was to desing and implement a sucure file sharing system that ensures top notch confidentiality, itergrity, and safe transer of data between users. 

## Tools and Technologies Used  

This prpoject leverages a combination of backend frameworks, cryptography libraries, and frontend technologies to create a secure and functional file-sharing app.  

**Tools and Technologies Used** 

- **Python Flask:** Backend framework for handling file uploads and download routes and encryption logic.  
- **PyCryptodome:** Python cryptography library used for implementing AES-256-GCM encryption and decryption.  
- **HTML:** Frontend UI for file upload and download  
- **dotenv:** Secure storage environment for storing encryption keys.  
- **Postman:** API testing tool for verifying uploads and downloads endpoints  
- **curl:** CLI for testing API request and encryption output  
- **Git & Github:** Version contol and collaboaration platform for managing project code.  
- **Checksum Tools(SHA256):** For verifying intergrity before and after encryption and decryption.  
- **Ngrok:** A tool used to create secure tunnel from your local machine to the internet.  
     

## 1. Setting up Flask in Vs code

On your terminal create a folder where you will be running your project, set up a virtual environemnt and install all the Flask packages. 
create a basic app that will encrypt files before uploading and decrypting when downloading. 

![screenshot](images/run.png)

### AES-GCM Encryption with Key Wrapping for Secure File Management
This code utilizes AES-GCM, which combines authentication in one step, which is mostly used in TLS/HTTPS and secure file storage. It also ensures that when someone tampers with the data, the tag verification fails during decryption, giving assurance of confidentiality and integrity. The same key used for encryption is the same key used to decrypt the data. This is achieved by wrapping the key with the master key stored encrypted together, proving good key management. 

![sreenshot](images/encryption.png)

### Core application files   
The following files were developed to implement the system    
- **app.py** - Flask application  
- **models.py** - Database models (SQLAlchemy)  
- **templates** - UI templates for file uploads and downloads  

### Running the application  

![sreeenshot](images/ui.png)

## System Architecture  

**Secure File Sharing System** was designed with layered architecture mainly basing its forcus on confidentiality, Intergrity and Availability.   

### Workflow  

1. **File Upload**    
User uploads the file using Flask web portal build on HTML, the file immediately is encrypted using **AES-256-GCM** before is stored. All metadata eg filename, upload date, filepath etc is stored in the database.  
2. **File Storage**  
Encrypted files are stored in the upload directory, this ensures that the files don't touch the disk ensuring confidentiality at rest.  
3. **File Download**  
The user request file from the server, the system immeadiatly decrypts the file using encryption keys. The file is decrypted and streamed to the client as plain text.  
4. **Key Management**  
Master key(32 bytes) long term key is stored in master.key in env which is used to wrap/unwrap Data Encryption Keys(DEKs). This DEKs are randoml generated per file which encrypts file's content with AES-GCM. Ciphertext are stored on disk and wrapped DEK stored in DB.
5. **Global Access Ngrok**  
This serves as a public gateway and lets remote users to test uploading/downloading files to the app while the system enforces encryption with Master Key + DEKs.  

### Use of ngrok for Global access 

**What is ngrok**  
- Ngrok is a tool that provide a secure tunnel to your local machine, allowing it to be accessed globaly via public URl.

**Why Ngrok**  
- **Zero-configuration tunneling:** Instantly expose local servers to the web withiout firewal or network configuration.  
- **HTTPS tunneling:** Encrypted connection to ensure secure access.
  
**Installing (Ngrok)**  

Register Ngrok from their website and get the authentication key.  

on your teminal 
```
ngrok config add-authtoken "YOUR TOKEN"
```
Start your tunnel  
```
ngrok http 5000
```
ngrok will give you a link that can be shared.   

![sreenshot](images/ngrok.png)


**Flow:** ==> File → encrypted with DEK → DEK wrapped with Master Key → both stored.   

![screenshot](images/keys.png)  

## CIA Triad - How it's Ensured  

**Confidentiality (AES 256 file encryption) ===> Integrity (SHA-256 hash + RSA signature) ===> Authentication (Digital signature from verified sender)**  

## Why AES? Why Not Other Algorithms?  

I chose AES for the following reasons:  

- **Performance:** AES is higly optimized for both hardware and softwares, ensuring fast encryption and decryption processes.
- **Security:** AES-256 is a global trusted standard, and resistant to all attacks.
- **Simpliciity:** AES uses a single key for both encryption/decryption, which simplies key management.
- **Wide Adoption:** AES is widely adopted and supported by many cryptographic libraries and hardware implementations.

## Risk and Migitigations  

While the system provides a strong baseline for secure file sharing, several risk remain that should remain that should be addressed in production env.  
1. **Key Exposure.**
   - If the leaked is leaked all the encrypted file could be exposed or compromised. To avoid such cases we implement a secure key management system (KMS) such as AWS KMS, HashiCorp Vault, or Azure Key Vault, which regularly rotate keys and restrict access through role based controls.
2. **Insecure Transmission.**
   - Without proper HTTPS/TLS configuration, files in transit may be intercepted, proper mitigation for this is to deploy Flask app behind HTTPS with TLS 1.3 enabled and use or valid certificates from Let's Encrypt and Trusted CA.
3. **Unauthorized Access.**
   - The system does not enforce user authentication, the best mitigation for this is to add authentication and Role Based Controls (RBC), which allows user to access thier own files.
4. **File Injection.**
   - Attackers may attemt to upload malicious files to the server this will be mitigated by enforcing file type validation, limit maximum file size, and intration of malware tools such as ClamAV.
5. **Denial of Attack(DoS) via large file Uploads**
   - Excessively large file uploads may exhaust server resources, this can be mitigated by configuring uploads size limits, and implementing rate limit.



## Recomendations  

To strengthen this system for real world deployment, I recommend the following should be improved.  

- Intergating Secure Key Managent by moving from static environment to a centralized KMS.
- Enabling Strong Authentication by implementing login functionslity with salted password hashing and session management.
- Auditing logs by maintaing detailed logs for uploads, downloads, and tampering for forensic analysis.
- Automating Backup and Recovery but making sure encrypted files should be backedup securely to prevent accidental loss.
- Continuous security testing by conducting regular penetration testing, fuzzing, and automated vulnerability scans.  



