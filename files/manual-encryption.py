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

# Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

# Message à crypter
message = "super!!!super!!!super!!!super!!!supe"

# Récupération du fichier .cap fourni - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

# rc4 seed est composé de IV+clé
seed = arp.iv+key

# Calcul du nouvel ICV en effectuant un CRC du message
# l'instruction & 0xffffffff permet de toujours retourner un icv positif
icv = binascii.crc32(message) & 0xffffffff
# Conversion de l'ICV au format int
icv_int = struct.pack('I', icv)

# Concaténation du message et de l'ICV
message_clear = message + icv_int

# Calcul du frame body en faisant keystream xor message_clear
cryptedText = rc4.rc4crypt(message_clear, seed)  

# Récupération de l'ICV crypté
icv_crypted=cryptedText[-4:]
(icv_numerique,)=struct.unpack('!L', icv_crypted)

# Récupération du message crypté
text_crypte=cryptedText[:-4] 

# Remplacement du wepData par le message crypté
arp.wepdata = text_crypte

# Remplacement de l'icv par l'icv crypté
arp.icv = icv_numerique

# Affichage de quelques information
print 'Text: ' + arp.wepdata.encode("hex")
print 'icv:  ' + icv_crypted.encode("hex")

# Ecriture de la nouvelle trame dans le fichier arp1.cap
wrpcap("arp1.cap", arp)