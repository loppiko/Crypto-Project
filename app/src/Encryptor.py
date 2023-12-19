import os

# Symmetric cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Asymetric cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymetric_padding

# Passwords managment
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# JSON
import base64
import json




# safety class
class SafetyExit(Exception): pass

def checkSource(fileSource: str):
    if ("toEncrypt" in fileSource): pass
    else: raise(SafetyExit("File source is not legal"))



# ------ File operations ------
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
    



# ------ Symmetric algorythms (file operations) ------
def symmetricEncryption(iv, key, binary, fileSource: str, hamming_code_function, hamming_code_error_function = None):
    checkSource(fileSource)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_binary = padder.update(hamming_code_function(binary, hamming_code_error_function)) + padder.finalize()
    
    encryptedBinary = encryptor.update(padded_binary) + encryptor.finalize()
    
    return saveBin(encryptedBinary, f"{fileSource}")



def symmetricDecryption(iv, key, binary, fileSource, hamming_code_function):
    checkSource(fileSource)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    unpadder = padding.PKCS7(128).unpadder()
    decryptedBinary = decryptor.update(binary) + decryptor.finalize()

    binaryFile = unpadder.update(decryptedBinary) + unpadder.finalize()

    return saveBin(hamming_code_function(binaryFile), fileSource)



# ------ Asymetric algorythms (key operations) ------

def saveAsymetricKey(private_key, savingFunction: None, fileSource: str, password):
    public_key = private_key.public_key()

    serialized_private = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.PKCS8,
        encryption_algorithm = serialization.BestAvailableEncryption(password.encode("utf-8"))
    )

    serialized_public = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )

    savingFunction(serialized_private, f"{fileSource}" + "private_key.pem")
    savingFunction(serialized_public, f"{fileSource}" + "public_key.pem")


def readAsymetricPrivate_Key(readingFunction: None, password, fileSource: str = ""):
    return serialization.load_pem_private_key(readingFunction(f"{fileSource}" + "private_key.pem"), password=password.encode("utf-8"), backend=default_backend())

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




# ------ File verification and signing ------

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


# ------ Passwords managment ------

class WrongPassword(Exception): pass

def hash_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=256398,
        length=32,
        salt=salt,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key


def generate_new_credentials(password_hashmap, login, input_pass, salt):
    password_hashmap[login] = {
        "hashed_password": binaryIntoBase64(hash_password(input_pass, salt)),
        "salt": binaryIntoBase64(salt)
    }
    return password_hashmap


def check_credentials(password_hashmap, login, input_pass, salt):
    return binaryIntoBase64(hash_password(input_pass, salt)) == password_hashmap[login]["hashed_password"]


# ------ Hamming Code ------


def apply_hamming_code(bytes_input, error_function):
    import Hamming_code
    bin_0_1 = Hamming_code.binary_into_0_and_1(bytes_input)

    bin_0_1_blocks = Hamming_code.divide_into_bit_blocks(bin_0_1, 4)

    hamming_code = Hamming_code.encode_hamming_code_4_into_7(bin_0_1_blocks, error_function)

    return b"".join([bytes([int(bit) for bit in bits]) for bits in hamming_code])

    


def restore_data_from_hamming_code(bytes_input):
    import Hamming_code
    hamming_code = Hamming_code.divide_into_bit_blocks(bytes_input, 7)

    bin_0_1_blocks = Hamming_code.decode_hamming_code_4_into_7(hamming_code)

    output_8_bits = Hamming_code.merge_4_bit_blocks_into_8_bits(bin_0_1_blocks)

    return bytes([int(block, 2) for block in output_8_bits])






# ------ MAIN ------

if __name__ == "__main__":
    config = readJson("config.json")

    keysFolderSource = config["keys_folder_source"]
    fileToEncrypt = config["file_to_encrypt"]
    signaturesFile = config["signatures_file"]
    password_hashmap = readJson(f"{config['password_file']}")


    print("Choose mode: encryption (1) or decryption (2)")


    while True:
        mode = input()
        
        if (mode == "1"): 
            print("Input your login: ")
            input_login = input()

            print("Input your password: ")
            input_pass = input()

            
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()

            if (password_hashmap.get(input_login) is not None):
                saveJson(generate_new_credentials(password_hashmap, input_login, input_pass, base64Intobinary(password_hashmap[input_login]["salt"])), f"{config['password_file']}")

            else:
                saveJson(generate_new_credentials(password_hashmap, input_login, input_pass, os.urandom(16)), config["password_file"])

            saveAsymetricKey(private_key, saveBin, keysFolderSource, input_pass)

            symetric_key = os.urandom(32)
            iv = os.urandom(16)

            saveBin(iv, f"{keysFolderSource}" + "iv.bin")
            saveBin(asymetric_encryption(public_key, symetric_key), f"{keysFolderSource}" + "key.bin")


            arrayWithSignatures = readJson(f"{signaturesFile}")
            saveJson(createDataSignature(arrayWithSignatures, private_key), f"{signaturesFile}")


            import Hamming_code

            # symmetricEncryption(iv, symetric_key, readBin(fileToEncrypt), fileToEncrypt, apply_hamming_code) # without errors
            symmetricEncryption(iv, symetric_key, readBin(fileToEncrypt), fileToEncrypt, apply_hamming_code, Hamming_code.encourage_error_function) # with errors



        elif (mode == "2"): 
            print("Input your login: ")
            input_login = input()

            print("Input your password: ")
            input_pass = input()


            try: 
                if (not check_credentials(password_hashmap, input_login, input_pass, base64Intobinary(password_hashmap[input_login]["salt"]))): 
                    raise WrongPassword
                else:
                    pass

            except WrongPassword:
                print(f"\npassword of user \'{input_login}\' does not match")
                exit()
            
            except KeyError:
                print(f"\n\'{input_login}\' does not exists in database")
                exit()

            private_key = readAsymetricPrivate_Key(readBin, input_pass, keysFolderSource)
            public_key = readAsymetricPublic_key(readBin, keysFolderSource)

            arrayWithSignatures = readJson(f"{signaturesFile}")
            verifyDataSignature(arrayWithSignatures, public_key)

            iv = readBin(f"{keysFolderSource}" + "iv.bin")
            symetric_key = asymetric_decryption(private_key, readBin(f"{keysFolderSource}" + "key.bin"))


            symmetricDecryption(iv, symetric_key, readBin(fileToEncrypt), fileToEncrypt, restore_data_from_hamming_code)            


        if (mode == "1" or mode == "2"): break