import json
from AES_code import AES
from ECC_code import ECC
import converter
def main():
    input_file = input("Name of file in test folder: ")
    file_type = input_file.split(".")[1]
    multimedia_data = converter.fileToBase64("test_files/" + input_file)
    print("Base64 encoded plaintext :",multimedia_data[0:100])
    aes_key = 0x5468617473206D79204B756E67204675
    # Encrypt  AES_key with ECC public key
    ecc_obj_AESkey = ECC.ECC()
    private_key = 0x837003BA87915F4F56135FCD16415D1C975AE0EF7E5963465180B4AE5C243580
    public_key = ecc_obj_AESkey.gen_pubKey(private_key)
    (C1_aesKey, C2_aesKey) = ecc_obj_AESkey.encryption(public_key, str(aes_key))
    # Encrypt the multimedia_data with AES algorithm
    aes = AES.AES(aes_key)
    encrypted_multimedia = aes.encryptBigData(multimedia_data)
    data_for_ecc = converter.makeSingleString(encrypted_multimedia)
    # Encrypt the encrypted_multimedia with ECC
    ecc = ECC.ECC()
    (C1_multimedia, C2_multimedia) = ecc.encryption(public_key, data_for_ecc)
    cipher = {
        "file_type": file_type,
        "C1_aesKey": C1_aesKey,
        "C2_aesKey": C2_aesKey,
        "C1_multimedia": C1_multimedia,
        "C2_multimedia": C2_multimedia,
        "private_key": private_key
    }
    with open('cipher.json', 'w') as fp:
        json.dump(cipher, fp)
    print('Encryption Done ')
if __name__ == "__main__":
    main()
