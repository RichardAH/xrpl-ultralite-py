import traceback
from datetime import datetime
from ecdsa import SigningKey, SECP256k1
from base58r import base58r
from socket import *
import select
from stlookup import *
import base64
import ssl
import urllib.request
import ripple_pb2
import binascii
import operator
import tlslite
import hashlib
import base64
import select
import ecdsa
import time
import json
import re
import math
import time
import os
import sys

def to_hex(x):
    if not type(x) == bytes:
        raise Exception("cannot to_hex() type " + str(type(x)))

    return str(binascii.hexlify(x), 'utf-8')

def from_hex(x):
    if not type(x) == str:
        raise Exception("cannot from_hex() type " + str(type(x)))

    return binascii.unhexlify(x)


def decode_xrpl_address(address):
    decoded = base58r.b58decode_check(address)
    if decoded[0] == 0 and len(decoded) == 21: # is an address
        return decoded[1:]
    else:
        raise ValueError("Not an AccountID!")

def encode_xrpl_address(b):
    if type(b) == str:
        b = from_hex(b)
    encoded = base58r.b58encode_check(b'\x00' + b)
    return str(encoded, 'utf-8')


def SHA512(b):
    h = hashlib.sha512()
    h.update(b)
    return h.digest()

#double sha256 and then return first four bytes, used for rippled node pub key
def SHA256CHK(b):
    h = hashlib.sha256()
    h.update(b)
    b = h.digest()
    h = hashlib.sha256()
    h.update(b)
    return h.digest()[0:4]

#sha512 half (first half)
def SHA512H(b):
   return SHA512(b)[0:32] 

#sha512 half with a prefix
def SHA512HP(p, b):
    return SHA512(b''.join([p, b]))[0:32]

#applies a byte by byte xor between two byte arrays
def XOR(b1, b2):
    return bytes(map(operator.xor, b1, b2))

class CPASS:
    msg = b''
    def __init__(self, msg):
        self.msg = msg

    def hexdigest(self):
        return str(self.msg, 'utf-8')

#convert from numerical message type to string
def peer_message_type_to_string(mtype):
    x = mtype
    if isinstance(x, str): return x
    if x == 1: return "mtHELLO"
    if x == 2: return "mtMANIFESTS"
    if x == 3: return "mtPING"
    if x == 4: return "mtPROOFOFWORK"
    if x == 5: return "mtCLUSTER"
    if x == 12: return "mtGET_PEERS"
    if x == 13: return "mtPEERS"
    if x == 15: return "mtENDPOINTS"
    if x == 30: return "mtTRANSACTION"
    if x == 31: return "mtGET_LEDGER"
    if x == 32: return "mtLEDGER_DATA"
    if x == 33: return "mtPROPOSE_LEDGER"
    if x == 34: return "mtSTATUS_CHANGE"
    if x == 35: return "mtHAVE_SET"
    if x == 41: return "mtVALIDATION"
    if x == 42: return "mtGET_OBJECTS"
    if x == 50: return "mtGET_SHARD_INFO"
    if x == 51: return "mtSHARD_INFO"
    if x == 52: return "mtGET_PEER_SHARD_INFO"
    if x == 53: return "mtPEER_SHARD_INFO"
    return "mtUNKNOWN!!!"

#convert from string based message type identifier to numerical 
def peer_message_type_to_number(x):
    if isinstance(x, int): return x
    x = x.lower()
    x = re.sub('^mt', '', x)
    x = re.sub('_', '', x)
    if x == "hello": return 1
    if x == "manifests": return 2
    if x == "ping": return 3
    if x == "proofofwork": return 4
    if x == "cluster": return 5
    if x == "getpeers": return 12
    if x == "peers": return 13
    if x == "endpoints": return 15
    if x == "transaction": return 30
    if x == "getledger": return 31
    if x == "ledgerdata": return 32
    if x == "proposeledger": return 33
    if x == "statuschange": return 34
    if x == "haveset": return 35
    if x == "validation": return 41
    if x == "getobjects": return 42
    if x == "getobjectsbyhash": return 42
    if x == "getobjectbyhash": return 42
    if x == "getshardinfo": return 50
    if x == "shardinfo": return 51
    if x == "getpeershardinfo": return 52
    if x == "peershardinfo": return 53
    return -1

#parse an incoming message from the connection excluding the 6 byte header
#which must have been already stripped and fed in as mtype
def parse_peer_message(mtype, msg):
    x = peer_message_type_to_number(mtype)
    try:
        if x == 1:
            ret = ripple_pb2.TMHello()
            ret.ParseFromString(msg)
            return ret
        if x == 2:
            ret = ripple_pb2.TMManifests()
            ret.ParseFromString(msg)
            return ret
        if x == 3:
            ret = ripple_pb2.TMPing()
            ret.ParseFromString(msg)
            return ret
        if x == 4:
            ret = ripple_pb2.TMProofWork()
            ret.ParseFromString(msg)
            return ret
        if x == 5:
            ret = ripple_pb2.TMCluster()
            ret.ParseFromString(msg)
            return ret
        if x == 12:
            ret = ripple_pb2.TMGetPeers()
            ret.ParseFromString(msg)
            return ret
        if x == 13:
            ret = ripple_pb2.TMPeers()
            ret.ParseFromString(msg)
            return ret
        if x == 15:
            ret = ripple_pb2.TMEndpoints()
            ret.ParseFromString(msg)
            return ret
        if x == 30:
            ret = ripple_pb2.TMTransaction()
            ret.ParseFromString(msg)
            return ret
        if x == 31:
            ret = ripple_pb2.TMGetLedger()
            ret.ParseFromString(msg)
            return ret
        if x == 32:
            ret = ripple_pb2.TMLedgerData()
            ret.ParseFromString(msg)
            return ret
        if x == 33:
            ret = ripple_pb2.TMProposeSet()
            ret.ParseFromString(msg)
            return ret
        if x == 34:
            ret = ripple_pb2.TMStatusChange()
            ret.ParseFromString(msg)
            return ret
        if x == 35:
            ret = ripple_pb2.TMHaveTransactionSet()
            ret.ParseFromString(msg)
            return ret
        if x == 41:
            ret = ripple_pb2.TMValidation()
            ret.ParseFromString(msg)
            return ret
        if x == 42:
            ret = ripple_pb2.TMGetObjectByHash()
            ret.ParseFromString(msg)
            return ret
        if x == 50:
            ret = ripple_pb2.TMGetShardInfo()
            ret.ParseFromString(msg)
            return ret
        if x == 51:
            ret = ripple_pb2.TMShardInfo()
            ret.ParseFromString(msg)
            return ret
        if x == 52:
            ret = ripple_pb2.TMGetPeerShardInfo()
            ret.ParseFromString(msg)
            return ret
        if x == 53:
            ret = ripple_pb2.TMPeerShardInfo()
            ret.ParseFromString(msg)
            return ret
    except:
        print("warning could not parse message of type " + str(x))
        return False
    return False

#encode a message object for sending out over the connection
#including the 6 byte message type and size header
def encode_peer_message(message_type, message):
    message_type = peer_message_type_to_number(message_type)
    if message_type < 0:
        print("unknown message type: " + str(message_type))
        return 0
    payload = message.SerializeToString()
    length = len(payload)
    buf = length.to_bytes(4, byteorder='big') + message_type.to_bytes(2, byteorder='big') + payload
    return buf 

#this is for a list of stobjects packed together
def parse_vlencoded(x):
    ret = []
    size = 0
    upto = 0
    while upto < len(x):
        if x[upto] < 193:
            size = x[upto]
            upto += 1
        elif x[upto] < 241:
            size = 193 + ((x[upto] - 193) * 256) + x[upto+1]
            upto += 2
        elif x[upto] < 255:
            size = 12481 + ((x[upto] - 241) * 65536) + (x[upto+1] * 256) + x[upto+2]
            upto += 3
        else:
            print("warning invalid vle lead byte: " + str(x[upto]))
            return False
        ret.append(x[upto:upto+size])
        upto += size
    return ret

def parse_stobject(x, print_out = False, hex_encoded_bin_fields = False):

    def add_entry(sto, fieldname, entry):
        if fieldname in sto and not type(sto[fieldname]) == list:
            sto[fieldname] = [sto[fieldname]]
        if fieldname in sto:
            sto[fieldname].append(entry)
        else:
            sto[fieldname] = entry
        

    try:
        indentlvl = 0
        root_sto = {}
        sto = root_sto
        stack = []
        inpath = False
        upto = 0
        while upto < len(x):
            if inpath:
                flags = x[upto]
                upto += 1
                #print("Flags: " + hex(flags))
                if flags == 0xFF:
                    continue
                elif flags == 0x00:
                    inpath = False
                    continue

                has_account     = not flags & 0x01 == 0
                has_currency    = not flags & 0x10 == 0
                has_issuer      = not flags & 0x20 == 0

                if has_account:
                    upto += 20 #todo: extract and store these values
                if has_currency:
                    upto += 20
                if has_issuer:
                    upto += 20

                continue

            typecode = 0
            fieldcode = 0
        
            high = x[upto] >> 4
            low = x[upto] & 0xF
            if high == 0 and low == 0:
                typecode = x[upto + 1]
                fieldcode = x[upto + 2]
                upto += 3
            elif high == 0 and low != 0:
                fieldcode = low
                typecode = x[upto + 1]
                upto += 2
            elif high != 0 and low == 0:
                typecode = high
                fieldcode = x[upto + 1]
                upto += 2
            else:
                typecode = high
                fieldcode = low
                upto += 1

            if not typecode in STLookup or not fieldcode in STLookup[typecode]:
                print("warning could not parse STObject, typecode = " + str(typecode) + ", fieldcode = " + str(fieldcode))
                upto +=1
                continue
                #return False

            if print_out and not ( (typecode == 14 or typecode == 15) and fieldcode == 1 ):
                print('\t'*indentlvl + STLookup[typecode][fieldcode]['field_name'] + ": ", end='')
                
            fieldname = STLookup[typecode][fieldcode]['field_name']

            is_amount = STLookup[typecode]['type_name'].lower() == 'amount'

            size = -1

            if STLookup[typecode][fieldcode]['vle']:
                if x[upto] < 193:
                    size = x[upto]
                    upto += 1    
                elif x[upto] < 241:
                    size = 193 + ((x[upto] - 193) * 256) + x[upto+1]
                    upto += 2
                elif x[upto] < 255:
                    size = 12481 + ((x[upto] - 241) * 65536) + (x[upto+1] * 256) + x[upto+2]
                    upto += 3
                else:
                    print("warning invalid vle lead byte: " + str(x[upto]))
                    return False
            elif 'size' in STLookup[typecode]:
                size = STLookup[typecode]['size']
            elif is_amount:
                # work out size from context
                if x[upto] >> 6 == 1:
                    # xrp
                    size = 8
                else:
                    # not xrp
                    size = 48
            elif typecode == 15 or typecode == 14: #object/array
                indentlvl += 1
                if fieldcode == 1:
                    indentlvl -= 2
                    if len(stack) > 0:
                        sto = stack.pop()
                else:
                    new_level = {}
                    add_entry(sto, fieldname, new_level)
                    stack.append(sto)
                    sto = new_level
 
                if print_out:
                    print("")
                continue
            elif typecode == 18:
                inpath = True
                continue
            
            #todo: convert numeric success/failure codes to readable/symbil form?
            #elif typecode == 16 and fieldcode == 3:
            #    val = int(to_hex(x[upto:upto+size]), 16)
                
            #    add_entry(sto, fieldname, val)
 
            else:
                print("warning could not determine size of stobject type=" + str(typecode) + " field=" + str(fieldcode))
                return False
                    

            if is_amount and size == 8:
                val = int(to_hex(x[upto:upto+size]), 16) - 0x4000000000000000
                add_entry(sto, fieldname, {"currency": "xrp",  "value": val})
                if print_out:
                    print ("XRP " + str(val/1000000))
            elif is_amount:

                #print("RAW AMOUNT DATA: " + to_hex(x[upto:upto+384]))

                curcode = str(x[upto+20:upto+23], 'utf-8')

                amount = 0
                if x[upto:upto+8] != b'\x80\x00\x00\x00\x00\x00\x00\x00':
                    #do the amount math since it's not the special zero case
                    # first 10 bits are flags and expontent, final 54 are mantissa
                    mantissa = 0
                    mantissa += (x[upto+1]&0b111111) << 48
                    mantissa += x[upto+2] << 40
                    mantissa += x[upto+3] << 32
                    mantissa += x[upto+4] << 24
                    mantissa += x[upto+5] << 16
                    mantissa += x[upto+6] << 8
                    mantissa += x[upto+7]

                    exponent = 0
                    exponent += x[upto] << 8
                    exponent += x[upto+1]
                    exponent >>= 6
                    exponent &= 0xFF
                   
                    # as per spec we need to sub 97 from exponent now 
                    exponent -= 97

                    sign = (x[upto] >> 7) & 1     
                
                    amount = mantissa * (10 ** exponent)
                    

                issuer = x[upto+28:upto+48]

                entry = {"Currency": curcode,  "Value": amount, "Issuer": issuer}
                if hex_encoded_bin_fields:
                    entry['Issuer'] = encode_xrpl_address(issuer)
                
                add_entry(sto, fieldname, entry)
                
                if print_out:
                    print (curcode + ": " + str(amount) + " [Issuer:" + encode_xrpl_address(issuer) + "]")

            elif size == 0:
                add_entry(sto, fieldname, None)
                if print_out:
                    print("<empty>")
            elif size <= 8:
                val = int(to_hex(x[upto:upto+size]), 16)
                add_entry(sto, fieldname, val)
                if print_out:
                    if 'flags' in STLookup[typecode][fieldcode]['field_name'].lower():
                        print( "{0:b}".format(val) )
                    else:
                        print(val)
            else:
                if print_out:
                    if typecode == 8:
                        print(encode_xrpl_address(x[upto:upto+size]))
                    else:
                        print( to_hex(x[upto:upto+size]))

                if hex_encoded_bin_fields:
                    if typecode == 8:
                        add_entry(sto, fieldname, encode_xrpl_address(x[upto:upto+size]))
                    else:
                        add_entry(sto, fieldname, to_hex(x[upto:upto+size]))
                else:
                    add_entry(sto, fieldname, x[upto:upto+size])

            upto += size

        return root_sto
    except Exception as e:
        print("failed to parse stobject")
        print(e)
        return root_sto

def decompress_node(nodedata):
    if not nodedata[-1] == 3:
        return nodedata

    blank_branch = from_hex('0' * 64)
    reconstructed_node = b''
    upto = 0
    for branch in range(0, 16):
        if upto + 32 < len(nodedata) and nodedata[upto + 32] == branch:
            reconstructed_node += nodedata[upto:upto+32]
            upto += 33
        else:
            reconstructed_node += blank_branch
   
    reconstructed_node += b'\x02'
    return reconstructed_node

# https://github.com/ripple/rippled/blob/fccb7e1c70549d2cf47800f9942171fb681b5648/src/ripple/app/ledger/Ledger.cpp#L65
#        std::uint32_t(info.seq),                                               4
#        std::uint64_t(info.drops.drops ()),                                    8
#        info.parentHash,                                                      32
#        info.txHash,                                                          32
#        info.accountHash,                                                     32
#        std::uint32_t(info.parentCloseTime.time_since_epoch().count()),        4
#        std::uint32_t(info.closeTime.time_since_epoch().count()),              4
#        std::uint8_t(info.closeTimeResolution.count()),                        1
#        std::uint8_t(info.closeFlags));                                        1
def parse_ledger_root(d):

    if len(d) != 118:
        return False

    return {
        "ledgerSeq": (d[0] << 24) + (d[1] << 16) + (d[2] << 8) + d[3],
        "drops":  (d[4] << 56) + (d[5] << 48) + (d[6] << 40) + (d[7] << 32) + (d[8] << 24) + (d[9] << 16) + (d[10] << 8) + d[11],
        "parentHash": d[12:44],
        "txHash": d[44:76],
        "accountHash": d[76:108],
        "parentCloseTime": (d[108] << 24) + (d[109] << 16) + (d[110] << 8) + d[111],
        "closeTime": (d[112] << 24) + (d[113] << 16) + (d[114] << 8) + d[115],
        "closeTimeResolution": d[116],
        "closeFlags": d[117]
    }
    


#this helper function will test each of the possible branches of an inner node against a searched for hash
def node_contains(node, findhash):
    for n in range(0, 512, 32):
        if node[n:n+32] == findhash:
            #print("Found " + to_hex(findhash) + " at branch " + str(n/32))
            return True
    return False      
