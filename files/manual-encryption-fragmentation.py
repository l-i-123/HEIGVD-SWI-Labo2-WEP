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

#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xab'
message1 = "Message numero 1, il y a une suite!!"
message2 = "Message numero 2, il y a une suite!!"
message3 = "Message numero 3, c'est le dernier!!"

#messageBin = binascii.a2b_base64(message)

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp1 = rdpcap('arp.cap')[0]
arp2 = rdpcap('arp.cap')[0]
arp3 = rdpcap('arp.cap')[0]

# rc4 seed est composé de IV+clé
seed1 = arp1.iv+key
seed2 = arp2.iv+key
seed3 = arp3.iv+key

# Calcul du nouvel ICV en effectuant un CRC du message
icv1 = binascii.crc32(message1) & 0xffffffff
icv2 = binascii.crc32(message2) & 0xffffffff
icv3 = binascii.crc32(message3) & 0xffffffff

a1 = struct.pack('I', icv1)
a2 = struct.pack('I', icv2)
a3 = struct.pack('I', icv3)

#texte en clair (message + ICV)
message_clear1=message1 + a1
message_clear2=message2 + a2
message_clear3=message3 + a3

#Calcul du keystream
cryptedText1 = rc4.rc4crypt(message_clear1, seed1)
cryptedText2 = rc4.rc4crypt(message_clear2, seed2)
cryptedText3 = rc4.rc4crypt(message_clear3, seed3)  

#récupération del'ICV crypté
icv_crypted1=cryptedText1[-4:]
icv_crypted2=cryptedText2[-4:]
icv_crypted3=cryptedText3[-4:]

(icv_numerique1,)=struct.unpack('!L', icv_crypted1)
(icv_numerique2,)=struct.unpack('!L', icv_crypted2)
(icv_numerique3,)=struct.unpack('!L', icv_crypted3)

#calcul du frame body en faisant keystream xor (data + ICV)
text_crypte1=cryptedText1[:-4]
text_crypte2=cryptedText2[:-4]
text_crypte3=cryptedText3[:-4]

#remplacement du wepData par le message crypté
arp1.wepdata = text_crypte1
arp2.wepdata = text_crypte2
arp3.wepdata = text_crypte3

#remplacement de l'icv par l'icv crypté
arp1.icv = icv_numerique1
arp2.icv = icv_numerique2
arp3.icv = icv_numerique3

arp1.FCfield.MF = True
arp2.FCfield.MF = True
arp2.SC += 1
arp3.FCfield.MF = False
arp3.SC += 2

arp = []
arp.append(arp1)
arp.append(arp2)
arp.append(arp3)

#for a in arp:
#    a.show()

wrpcap("arp2.cap", arp)