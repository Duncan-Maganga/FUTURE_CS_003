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

## Tools and Methodology  

**Target:** Creating a Secure File Sharing System     
**Tools:** Ngrok, curl, Postman, Signal, ProtonMail, Keybase, Flask, VS Code    
**Approach:**  
            - Set up Flask to run the project creating virtual invirnment and installing pycryptodome  
            - Creating a basic route to handle uploads and downloads.    
            - Implement AES encryption rules and key management.    
            - Creating a basic HTML template containing basic login and handling file uploads and downloads.    
            - Testing with Postman and curl. 
            

## 1. Setting up Flask in Vs code

On your terminal create a folder where you will be running your project, set up a virtual environemnt and install all the Flask packages. 
create a basic app that will encrypt files before uploading and decrypting when downloading. 

### Quickstart  
This code has utilizes AES-GCM which combines authenticationin one step which is mostly used in TLS/HTTPS and secure file storage, it also ensures that when someone tampers with the data the tag verification fails during decryption, giving assuarance of confidentiality and integrity. 
The same key used for encryption is the same key used to decrypt the data this is achieved by wrapping the key with the master key stored encrypted together proving good key management.

