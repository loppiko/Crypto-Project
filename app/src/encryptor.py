import os

# Symmetric cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Asymetric cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymetric_padding

#JSON
import base64
import json


# safety class
class SafetyExit(Exception): pass

def checkSource(fileSource: str):
    if ("toEncrypt" in fileSource): pass
    else: raise(SafetyExit("File source is not legal"))



# file operations
def readBin(fileSource: str): 
    with open(fileSource, "rb") as file:
        return file.read()
    

def saveBin(data, fileSource: str):
    with open(fileSource, "wb") as file:
        return file.write(data)
    

def readJson(fileSource: str):
    return json.loads(readBin(fileSource))


def saveJson(data, fileSource: str):
    with open(fileSource, 'w') as file:
        file.write(json.dumps(data, indent=4))


def binaryIntoBase64(binary: bytes):
    return base64.b64encode(binary).decode('utf-8')


def base64Intobinary(data):
    return base64.b64decode(data)
    



# symmetric algorythms (file operations)
def symmetricEncryption(iv, key, binary, fileSource: str):
    checkSource(fileSource)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_binary = padder.update(binary) + padder.finalize()
    
    encryptedBinary = encryptor.update(padded_binary) + encryptor.finalize()
    
    return saveBin(encryptedBinary, f"{fileSource}")



def symmetricDecryption(iv, key, binary, fileSource):
    checkSource(fileSource)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    unpadder = padding.PKCS7(128).unpadder()
    decryptedBinary = decryptor.update(binary) + decryptor.finalize()

    binaryFile = unpadder.update(decryptedBinary) + unpadder.finalize()

    return saveBin(binaryFile, fileSource)



# asymetric algorythms (key operations)

def saveAsymetricKey(private_key, savingFunction: None, fileSource: str):
    public_key = private_key.public_key()

    serialized_private = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.PKCS8,
        encryption_algorithm = serialization.NoEncryption()
    )

    serialized_public = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )

    savingFunction(serialized_private, f"{fileSource}" + "private_key.pem")
    savingFunction(serialized_public, f"{fileSource}" + "public_key.pem")


def readAsymetricPrivate_Key(readingFunction: None, fileSource: str = ""):
    return serialization.load_pem_private_key(readingFunction(f"{fileSource}" + "private_key.pem"), password=None)

def readAsymetricPublic_key(readingFunction: None, fileSource: str):
    return serialization.load_pem_public_key(readingFunction(f"{fileSource}" + "public_key.pem"), backend=None)


def asymetric_encryption(public_key, data: bytes):
    return public_key.encrypt(
        data,
        asymetric_padding.OAEP(
        mgf = asymetric_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm = hashes.SHA256(),
        label = None
        )
    )

def asymetric_decryption(private_key, data: bytes):
    return private_key.decrypt(
        data,
        asymetric_padding.OAEP(
        mgf = asymetric_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm = hashes.SHA256(),
        label = None
        )
    )


# File verification and signing

def createDataSignature(array: list, private_key):
    for hashmap in array:

        binaryData = private_key.sign(
            readBin(hashmap["fileSource"]),
            asymetric_padding.PSS(
                mgf=asymetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        hashmap["signature"] = binaryIntoBase64(binaryData)

    return array


def verifyDataSignature(array: list, public_key):
    for hashmap in array:        
        public_key.verify(
            base64Intobinary(hashmap["signature"]),
            readBin(hashmap["fileSource"]),
            asymetric_padding.PSS(
                mgf=asymetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )


keysFolderSource: str = "credentials/"
fileToEncrypt: str = "toEncrypt/e2.docx"
signaturesFile: str = "credentials/signatures.json"


print("Choose mode: encryption (1) or decryption (2)")


while True:
    mode = input()
    
    if (mode == "1"): 
        
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        saveAsymetricKey(private_key, saveBin, keysFolderSource)

        symetric_key = os.urandom(32)
        iv = os.urandom(16)

        saveBin(iv, f"{keysFolderSource}" + "iv.bin")
        saveBin(asymetric_encryption(public_key, symetric_key), f"{keysFolderSource}" + "key.bin")


        arrayWithSignatures = readJson(f"{signaturesFile}")
        saveJson(createDataSignature(arrayWithSignatures, private_key), f"{signaturesFile}")


        symmetricEncryption(iv, symetric_key, readBin(fileToEncrypt), fileToEncrypt)



    elif (mode == "2"): 
        private_key = readAsymetricPrivate_Key(readBin, keysFolderSource)
        public_key = readAsymetricPublic_key(readBin, keysFolderSource)

        arrayWithSignatures = readJson(f"{signaturesFile}")
        verifyDataSignature(arrayWithSignatures, public_key)

        iv = readBin(f"{keysFolderSource}" + "iv.bin")
        symetric_key = asymetric_decryption(private_key, readBin(f"{keysFolderSource}" + "key.bin"))
        symmetricDecryption(iv, symetric_key, readBin(fileToEncrypt), fileToEncrypt)



    if (mode == "1" or mode == "2"): break