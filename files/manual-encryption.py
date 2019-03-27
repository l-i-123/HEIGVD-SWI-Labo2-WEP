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
message = "super message encrypté"

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0] 

# rc4 seed est composé de IV+clé
seed = arp.iv+key 

# Calcul du nouvel ICV en effectuant un CRC du message
arp.icv = binascii.crc32(message)
icv_clear='{:x}'.format(arp.icv).decode("hex")

#texte en clair (message + ICV)
message_clear=message + icv_clear


#Calcul du keystream
cryptedText = rc4.rc4crypt(message_clear, seed)  

#récupération del'ICV crypté
icv_crypted=cryptedText[-4:]
(icv_numerique,)=struct.unpack('!L', icv_crypted)

#calcul du frame body en faisant keystream xor (data + ICV)
text_crypte=cryptedText[:-4] 

#remplacement du wepData par le message crypté
arp.wepdata = text_crypte

#remplacement de l'icv par l'icv crypté
arp.icv = icv_numerique

wrpcap("arp1.cap", arp)
