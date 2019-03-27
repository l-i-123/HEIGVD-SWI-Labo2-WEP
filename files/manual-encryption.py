#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
import rc4

#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'
iv = 0x000000
message = "super message encrypté"

# rc4 seed est composé de IV+clé
seed = iv+key 

# Calcul de l'ICV en effectuant un CRC du message
icv = binascii.crc32(message)

# Génération de la chaine à XOR avec le keystream
data_to_encrypt = message + icv

#Calcul du keystream
keyStream=rc4.rc4crypt(seed)  

#calcul du frame body en faisant keystream xor (data + ICV)
operator.xor(data_to_encrypt, keyStream)

#Génération de la trame (MAC Header + IV Header + Frame Body + ICV + CRC)
#frame = 

print 'Text: ' + text_enclair.encode("hex")
print 'icv:  ' + icv_enclair.encode("hex")
print 'icv(num): ' + str(icv_numerique)
