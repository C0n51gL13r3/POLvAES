"""  AES kütüphanelerini import ediyoruz  """
from Crypto.Cipher import AES
from secrets import token_bytes
#####################################################################################################################################################################################
#####################################################################################################################################################################################
"""  Polybius Encryption  """
def polybiusEncrypt(s):
    encrypt = ""

    for char in s:
        row = int((ord(char.lower())- ord('a')) / 5) + 1
        col = ((ord(char.lower()) - ord('a')) % 5) + 1
        
        if char == 'k':
            row = row - 1
            col = 5 - col + 1
            
        elif ord(char) >= ord('j'):
            if col == 1:
                col = 6
                row = row - 1
            col = col - 1
        r= str(row)
        c= str(col)
        encrypt = encrypt+r+c
    return encrypt

plaintext = input("Şifrelenecek Metni Giriniz : ")
encrypt = polybiusEncrypt(plaintext)

##################################################################################################################################################################################### 
#####################################################################################################################################################################################

"""  AES Encryption  """
key = token_bytes(16)

def AES_encrypt(message):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('ascii'))
    return nonce, ciphertext, tag

#####################################################################################################################################################################################
#####################################################################################################################################################################################

"""  AES Decryption  """
def AES_decrypt(nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce = nonce)
    plaintext2 = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext2.decode('ascii')
    except:
        return False

nonce, ciphertext, tag = AES_encrypt(encrypt)
plaintext2 = AES_decrypt(nonce, ciphertext, tag)
print("Şifrelenmiş Metin : ",ciphertext)

#####################################################################################################################################################################################
#####################################################################################################################################################################################

"""  Polybius Decryption  """
def polybiusDecrypt(s):
    s1 = list(s)
    decrypt = ""
    
    for i in range(0,len(s),2):
        r = int(s1[i])
        c = int(s1[i+1])
        ch = chr(((r-1)*5+c+96))
        if(ord(ch)-96>=10):
            ch=chr(((r-1)*5+c+96+1))
        ch1 = str(ch)
        decrypt = decrypt + ch1
    return decrypt

decrypt = polybiusDecrypt(encrypt)
print("Çözülmüş Metin : ",decrypt)
