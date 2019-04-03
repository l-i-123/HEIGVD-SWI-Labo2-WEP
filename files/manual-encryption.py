#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key """

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
import rc4
import os

'''
def bitstring_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])
'''

#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xab'
message = "surprisemotherfuckersurprisemotherfu"
#messageBin = binascii.a2b_base64(message)

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]
arp.show()
# rc4 seed est composé de IV+clé
seed = arp.iv+key
# Calcul du nouvel ICV en effectuant un CRC du message
icv = binascii.crc32(message) & 0xffffffff
a = struct.pack('I', icv)
 #01001010 10101100 11111011 10101111
#a = hex_bytes(0x7FFFFFFF)


#print(bitstring_to_bytes(icv))
#our_bytes = icv.to_bytes(4, byteorder='big', signed=True)

#icv = "0x4AACFBAF"
#icv_bytes = bytes(icv)
#icv_encrypted='{:x}'.format(icv).encode("bytes")
#icv_clear='{:x}'.format(icv).decode("hex")

#texte en clair (message + ICV)
message_clear=message + a


#cryptedMessage = rc4.rc4crypt(message, seed)
#cryptedICV = rc4.rc4crypt(icv, seed)
#Calcul du keystream
cryptedText = rc4.rc4crypt(message_clear, seed)  

#récupération del'ICV crypté
icv_crypted=cryptedText[-4:]
(icv_numerique,)=struct.unpack('!L', icv_crypted)

#calcul du frame body en faisant keystream xor (data + ICV)
text_crypte=cryptedText[:-4] 

#remplacement du wepData par le message crypté
arp.wepdata = text_crypte
#arp.wepdata = cryptedMessage

#remplacement de l'icv par l'icv crypté
#icv_clear=struct.unpack("!L", icv_crypted)
#arp.icv = long(icv_numerique)
#icv_clear='{:x}'.format(icv_crypted).decode("hex")
#arp.icv = icv_numerique
arp.icv = icv_numerique

print 'Text: ' + arp.wepdata.encode("hex")
print 'icv:  ' + icv_crypted.encode("hex")
#print 'icv(num): ' + str(a)

wrpcap("arp1.cap", arp)