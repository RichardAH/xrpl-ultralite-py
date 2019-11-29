# XRPL UltraLite
#   Author: Richard Holland

#change this to localhost if you want to connect to your own node
#todo: add a peer list that is updated when connecting
#todo: add UNL
bootstrap_server = "s1.ripple.com:51235" #this will be connected to if no peers are currently available from the peer file
full_history_peers = ["s2.ripple.com"] # we will use these to backfill our transaction history
UNL = [] #we'll populate from the below if specified
validator_site = "https://vl.ripple.com"
peer_file = "peers.txt"

PEER_CON_LIMIT = 1#3

import traceback
from interval import IntervalSet
from datetime import datetime
from ecdsa import SigningKey, SECP256k1
from base58r import base58r
from socket import *
import select
from stlookup import *
import base64
import ssl
import urllib.request
import pprint
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

argv = sys.argv[1:]

accounts = {}

peers = set()

connections = {}

if os.path.exists(peer_file):
    f = open(peer_file, "r+")
    if f:
        content = f.readlines()
        f.close()
        for ip in content:
            peers.add(ip)
   
peers.add(bootstrap_server)

def tohex(x):
    if not type(x) == bytes:
        raise Exception("cannot tohex() type " + str(type(x)))

    return str(binascii.hexlify(x), 'utf-8')

def fromhex(x):
    if not type(x) == str:
        raise Exception("cannot fromhex() type " + str(type(x)))

    return binascii.unhexlify(x)


def PPRINT(x):
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(x)

def decode_xrpl_address(address):
    decoded = base58r.b58decode_check(address)
    if decoded[0] == 0 and len(decoded) == 21: # is an address
        return decoded[1:]
    else:
        raise ValueError("Not an AccountID!")

def encode_xrpl_address(b):
    if type(b) == str:
        b = fromhex(b)
    encoded = base58r.b58encode_check(b'\x00' + b)
    return str(encoded, 'utf-8')


def TIME():
    return int(datetime.timestamp(datetime.now()))

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

#convert from numerical message type to string
def MT_TO_STR(mtype):
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
#this is designed to be human friendly, you can specify the messages
#in any case and without the prefix or underscores
def MT_TO_NUM(x):
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
def PARSE_MESSAGE(mtype, msg):
    x = MT_TO_NUM(mtype)
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
def ENCODE_MESSAGE(message_type, message):
    message_type = MT_TO_NUM(message_type)
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

def parse_stobject(x, print_out = False):

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

            else:
                print("warning could not determine size of stobject type=" + str(typecode) + " field=" + str(fieldcode))
                return False
                    

            if is_amount and size == 8:
                val = int(tohex(x[upto:upto+size]), 16) - 0x4000000000000000
                add_entry(sto, fieldname, {"currency": "xrp",  "value": val})
                if print_out:
                    print ("XRP " + str(val/1000000))
            elif is_amount:

                #print("RAW AMOUNT DATA: " + tohex(x[upto:upto+384]))

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

                add_entry(sto, fieldname, {"currency": curcode,  "value": amount, "issuer": issuer})
                
                if print_out:
                    print (curcode + ": " + str(amount) + " [Issuer:" + encode_xrpl_address(issuer) + "]")

            elif size == 0:
                add_entry(sto, fieldname, None)
                if print_out:
                    print("<empty>")
            elif size <= 8:
                val = int(tohex(x[upto:upto+size]), 16)
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
                        print( tohex(x[upto:upto+size]))

                add_entry(sto, fieldname, x[upto:upto+size])

            upto += size

        return root_sto
    except Exception as e:
        print("failed to parse stobject")
        print(e)
        return root_sto

#generate a node key
node_sk = SigningKey.generate(curve=SECP256k1)
node_vk = node_sk.get_verifying_key()
#node key must be in compressed form (x-coord only) and start with magic type 0x1C
order = ecdsa.SECP256k1.generator.order()
point = node_vk.pubkey.point
x = (b'\x1c\x02', b'\x1c\x03')[point.y() & 1] + ecdsa.util.number_to_string(point.x(), order)
y = SHA256CHK(x) #checksum bytes
x += y
#encode node key into standard base58 notation using the ripple alphabet
node_b58pk = base58r.b58encode(x).decode('utf-8')

x = None
y = None

def CONNECT(server):
    server = server.replace("\r", "")       
    server = server.replace("\n", "")       
    print("Attempting to connect to " + server + ", connections=" + str(len(connections)) )
    
    parts = server.split(":")
    port = 51235
    if (len(parts) > 0):
        port = int(parts[1], 10)
    server = parts[0]


    #open the socket
    sock = socket(AF_INET, SOCK_STREAM)
    try:
        sock.settimeout(1.0)
        sock.connect( (server, port))
    except Exception as e:
        #traceback.print_exception(e) 
        return False

    

    #attach the tls class  /  this tls lib has been modified to expose the finished messages for use in the rippled cookie
    connection = tlslite.TLSConnection(sock)
    connection.handshakeClientCert()

    #extract and calculate message hashes
    cookie1 = SHA512(connection.remoteLastMessage())
    cookie2 = SHA512(connection.localLastMessage())
    cookie = SHA512H(XOR(cookie1, cookie2))

    #the cookie must be signed with our private key
    sig = base64.b64encode(node_sk.sign_digest(cookie, sigencode=ecdsa.util.sigencode_der)).decode('utf-8')

    #finally construct the GET request which will allow us to say hello to the rippled server
    request =  'GET / HTTP/1.1\r\n'
    request += 'User-Agent: rippled-1.3.1\r\n'
    request += 'Upgrade: RTXP/1.2\r\n'
    request += 'Connection: Upgrade\r\n'
    request += 'Connect-As: Peer\r\n'
    request += 'Crawl: private\r\n'
    request += 'Session-Signature: '+sig+'\r\n'
    request += 'Public-Key: '+node_b58pk+'\r\n\r\n'

    #send the request
    connection.send(bytes(request, 'utf-8'))
    return connection

def FINISH_CONNECTING(connection,  packet):
    #the first packet will still be http
    #packet = connection.recv(1024).decode('utf-8')

    if (type(packet) == bytes):
        packet = packet.decode('utf-8')

    #we should get back the 'switching protocols' packet
    if not "Switching Protocols" in packet:
        if "{\"peer-ips\":" in packet:
            parts = packet.split("\r\n\r\n", 1) 
            content = parts[1]
            if "Transfer-Encoding: chunked" in packet:
                content_parsed = ""
                while len(content) > 0:
                    chunk_size = ""
                    while content[0:1] != "\r" and len(content) > 0:
                        chunk_size += content[0:1]
                        content = content[1:]
                    #skip \r\n
                    content = content[2:]
                    #parse size
                    if len(chunk_size) == 0:
                        break
                    chunk_size = int(chunk_size, 16)
                    content_parsed += content[0:chunk_size]
                    content = content[chunk_size:]
                content = content_parsed
            peer_ips = json.loads(content)["peer-ips"]

            for x in peer_ips:
                x = x.replace('[::ffff:', '').replace(']', '')   
                if re.match(r'^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}$', x):
                    if not x in peers:
                        peers.add(x)
                        #f = open(peer_file, "a+")
                        #if f:
                        #    f.write(x + "\n")
                        #    f.close()                    
                    return False #CONNECT(x)
  
        else:
            print("Failed to connected, received:")
            print(packet)
       
        print("failed") 
        return False

    #there's some interesting info in this header
    server_version = ""
    server_key = ""
    server_closed_ledger = ""
    server_private = ""

    headers = packet.split("\r\n")
    #collect the interesting info
    for fh in headers:
        if ": " in fh:
            ph = fh.split(": ") 
            if ph[0] == "Server":
                server_version = ph[1]
                print("node version: " + server_version) 
            elif ph[0] == "Public-Key":
                server_key = ph[1]
                print("node key: " + server_key)
            elif ph[0] == "Closed-Ledger":
                server_closed_ledger = ph[1]
                print("last closed ledger: " + server_closed_ledger)
            elif ph[0] == "Crawl":
                server_private = ph[1] == "private" 
                print("server is " + ("private" if server_private else "public"))

    #NB: execution to this point means the connection was successful
    return connection


# request account state object from a recently closed ledger
def REQUEST_LOOP():

    # data may come in asynchronously
    # so we collect it all first and then compute at the end
    request_state = {}
   
    last_ledger_seq_no = -1
 
    def new_state():
        ret = {
            "requested_ledger_hash": False,
            "calculated_ledger_hash": False,
            "reported_account_root_hash": False,
            "calculated_account_root_hash": False,
            "got_base_data" :  False,
            "accounts": {}
        }
        print(accounts)
        for acc in accounts:
            ret['accounts'][acc] = { 
                "asroot_key" : accounts[acc]['asroot_key'],
                "account_depth": False,
                "account_key": False,
                "account_path_nodes": {}, #these are the inner nodes that lead down to the account, including root, indexed by depth
                "got_account_data" :  False,
                "acc_seq_no":  -1, #last account sequence number
                "last_tx_ledger_seq_no": -1, #last ledger a transaction changed this account
                "last_tx_id": '',
                "proven_correct": False #indicates all the hashes have been checked up the tree
            }
        return ret

    def verify_as_nodes(state):

        for acc in state['accounts']:
            astate = state['accounts'][acc]
            if not state['got_base_data'] or not astate['got_account_data']:
                print('waiting for account/base data') 
                return False

        proven_correct_count = 0

        for acc in state['accounts']:

            astate = state['accounts'][acc]

            if astate['proven_correct']:
                proven_correct_count += 1 
                continue

            # check the hashes, if any don't match we'll return early with the default proven_correct value (False)
            if state["requested_ledger_hash"] != state["calculated_ledger_hash"]:
                print("requested ledger doesn't match calculated ledger")
                return True

            if state["reported_account_root_hash"] != state["calculated_account_root_hash"]:
                print("account root hash doesn't match")
                return True

            if astate["account_depth"] + 1 != len(astate["account_path_nodes"]):
                print("account depth doesn't match / missing inner nodes")
                return True

            #this helper function will test each of the possible branches of an inner node against a searched for hash
            def node_contains(node, findhash):
                for n in range(0, 512, 32):
                    if node[n:n+32] == findhash:
                        #print("Found " + tohex(findhash) + " at branch " + str(n/32))
                        return True
                return False      

            #compute up the tree now
            for i in range(astate['account_depth'], 0, -1):
                computed_hash = b''
                if i == astate['account_depth']: #leaf node is computed with MLN\0 not MIN\0
                    computed_hash = SHA512H(b'MLN\x00' + astate['account_path_nodes'][i][:-1])
                else:
                    computed_hash = SHA512H(b'MIN\x00' + astate['account_path_nodes'][i][:-1])
                if not node_contains(astate['account_path_nodes'][i-1], computed_hash):
                    print("inner node at depth " + str(i) + " computed hash " + tohex(computed_hash) + " wasn't found in the node above")
                    return True

            astate["proven_correct"] = True 
            proven_correct_count += 1

        if len(state['accounts']) == proven_correct_count:
            print("all proven correct")
        return len(state['accounts']) == proven_correct_count

    def decompress_node(nodedata):
        if not nodedata[-1] == 3:
            return nodedata

        blank_branch = fromhex('0' * 64)
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

    def process_as_node(ledger_hash, x, nodeid = False):

        if not ledger_hash in request_state:
            print("2 we were sent a ledger base we didn't ask for " + tohex(ledger_hash))
            return

        state = request_state[ledger_hash]

        nodetype = x.nodedata[-1]
        if hasattr(x, 'nodeid') and nodeid == False:
                nodeid = x.nodeid
        depth = nodeid[-1]
        nodehash = False
        
        for acc in state['accounts']:
            astate = state['accounts'][acc]
            key = astate['asroot_key']
            if not nodeid.hex()[:depth] == key[:depth]:
                continue

            x.nodedata = decompress_node(x.nodedata)

            #this is inefficient due to adding the account loop above, consider caching
            #if nodetype == 3: # inner node, compressed wire format, decompress...
            #    blank_branch = fromhex('0' * 64)
            #    reconstructed_node = b''
            #    upto = 0
            #    for branch in range(0, 16):
            #        if upto + 32 < len(x.nodedata) and x.nodedata[upto + 32] == branch:
            #            reconstructed_node += x.nodedata[upto:upto+32]
            #            upto += 33
            #        else:
            #            reconstructed_node += blank_branch
            #   
            #    reconstructed_node += b'\x02'
            #    x.nodedata = reconstructed_node
            nodetype = x.nodedata[-1]
           
            # execution to here means it's either a leaf or uncompressed 
            
            nodehash = SHA512H(b'MIN\x00' + x.nodedata[:-1])
            

            astate["account_path_nodes"][depth] = x.nodedata
            
            print("AS KEY: " + nodeid.hex())

            if nodetype == 1: # leaf node, wire format
                #this is our sought after account
                nodehash = SHA512H(b'MLN\x00' + x.nodedata[:-1])
                astate["account_key"] = nodeid
                astate["account_depth"] = nodeid[-1]
                astate["reported_account_hash"] = x.nodedata[-33:-1]
                print("FOUND: " + tohex(astate["reported_account_hash"]))
                sto = parse_stobject(x.nodedata[:-33], True)
                astate['got_account_data'] = True
                astate['acc_seq_no'] = sto['Sequence']
                astate['last_tx_id'] = sto['PreviousTxnID']
                astate['last_tx_ledger_seq_no'] = sto['PreviousTxnLgrSeq']

            elif nodetype != 2: # inner node, compressed, wire format
                print("UNKNOWN NODE " + str(nodetype))

        return nodehash 

    def request_tx(ledger_seq_no, txid):
        return request_tx_batch([(ledger_seq_no, ledger_seq_no + 5, txid)])

    def request_tx_batch(tuples):
        nonlocal last_ledger_seq_no
        seq_tx_map = {}

        for t in tuples:
            for n in range(t[0], t[1]+1):
                if not n in seq_tx_map:
                    seq_tx_map[n] = []
                seq_tx_map[n].append((t[2], t[3]))       

        for ledger_seq_no in seq_tx_map:
            if ledger_seq_no > last_ledger_seq_no:
                continue
            
            lentosend = len(seq_tx_map[ledger_seq_no])

            packets = lentosend//40 + 1

            for p in range(0, packets):
                appended = 0

                gl = ripple_pb2.TMGetLedger()
                gl.ledgerSeq = ledger_seq_no
                gl.itype = ripple_pb2.TMLedgerInfoType.liTX_NODE
                
                count = 0
                for txid, depth in seq_tx_map[ledger_seq_no]:
    
                    if not count >= p*20:
                        count += 1
                        continue

                    if count >= (p+1) * 20:
                        break

                    count += 1

                    if type(txid) == bytes:
                        txid = tohex(txid)

                    #print("requesting " + txid + " from ledger " + str(ledger_seq_no))
                    for l in range(1, depth, 1):
                        v = hex(l)[2:]
                        key = txid[0:l] + ('0' * (66 - l - len(v))) + v
                        gl.nodeIDs.append(fromhex(key))
                        appended += 1

                if appended > 0:
                    print("sending tx req batch p=" + str(p) + " count=" + str(count) + " contains=" + str(appended))
                    gl.queryDepth = 0
                    msg = ENCODE_MESSAGE('mtGetLedger', gl)
                    con = send_rand_peer(msg)
                    if con and connections[con]:
                        connections[con]['requests'] += 1

                    #send to a second random peer to increase chance of response
                    if len(connections) > 1:
                        con = send_rand_peer(msg, [con])
                        if con and connections[con]:
                            connections[con]['requests'] += 1

    #unfinished
    def fetch_acc_txs(state):
        for acc in state['accounts']:
            print("fetch acc txs: " + acc)
            astate = state['accounts'][acc]
            account = accounts[acc]
            processed_seq_nos = account['txseq']
            if not processed_seq_nos.contains(astate['acc_seq_no']):
                request_tx(astate['last_tx_ledger_seq_no'], astate['last_tx_id'])       

            continue
            #todo: place back-fetch on another thread/process

            # find out if there is at least one missing old transaction in our tx history
            if not processed_seq_nos.contains.last_missing() == False:
                # there is, so we need to first crawl backwards through the tx we have until we 
                # find this missing one
                txid = astate['last_tx_id']
                
                while os.path.exists(acc + "/tx/" + txid):
                    f = open(acc + "/tx/" + txid, "rb")
                    if not f:
                        break

                    tx = f.read()
                    f.close()

                    tx = parse_stobject(tx, True)


            # todo: start a clock and request retry counter to attempt to fetch these tx before trying a history node
   
    def send(connection, x):
        try:
            connection.send(x)
            return connection
        except:
            if connection in connections:
                del connections[connection]  
            print("send to connection fd=" + str(connection.fileno()) + " failed, removing connection")
            return False        

    def send_rand_peer(x, exclude = []):
        sent = False
        while len(connections) > len(exclude) and not sent:
            peer = [*connections][int(tohex(os.urandom(4)), 16) % len(connections)]
            if peer in exclude:
                continue
            sent = send(peer, x)
        return sent


    def request_wanted_tx():
        tx_set = []
        tx_drop = []
        for acc in accounts:
            for txid in accounts[acc]['wanted_tx']:
                if accounts[acc]['wanted_tx'][txid]['ledger_seq_no_at_discovery'] <= 0:
                    accounts[acc]['wanted_tx'][txid]['ledger_seq_no_at_discovery'] = ledger_seq - 1

                maxseq = accounts[acc]['wanted_tx'][txid]['max_ledger_seq_no']
                minseq = accounts[acc]['wanted_tx'][txid]['ledger_seq_no_at_discovery']
                if accounts[acc]['wanted_tx'][txid]['aggression'] == 3:
                    minseq += 1
                    maxseq = minseq + 1 
                #if maxseq < last_ledger_seq_no and maxseq + 5 > last_ledger_seq_no :
                if maxseq + 20 < last_ledger_seq_no:
                    tx_drop.append(txid)       
                elif minseq <= last_ledger_seq_no :
                    tx_set.append( (minseq, maxseq, txid, 12 ) ) #accounts[acc]['wanted_tx'][txid]['aggression']) )
                    
                    if last_ledger_seq_no - accounts[acc]['wanted_tx'][txid]['ledger_seq_no_at_discovery'] > 2:
                        accounts[acc]['wanted_tx'][txid]['aggression'] += 1
                        if accounts[acc]['wanted_tx'][txid]['aggression'] > 8:
                            accounts[acc]['wanted_tx'][txid]['aggression'] = 8

        for txid in tx_drop:
            for acc in accounts:
                print("DROPPED " + tohex(txid) + " ledger_added: " + str(accounts[acc]['wanted_tx'][txid]['ledger_seq_no_at_discovery']) + " max: " + str(accounts[acc]['wanted_tx'][txid]['max_ledger_seq_no']))
                accounts[acc]['dropped_tx'].append(txid)
                del accounts[acc]['wanted_tx'][txid]

        request_tx_batch(tx_set)
 
    #partial_message = []
    #partial_message_size = 0
    #partial_message_upto = 0

    partial = {}

    validations = {}

    #message loop

    def make_random_connection():
        server = [*peers][int(tohex(os.urandom(4)), 16) % len(peers)]   
        try:
            connection = CONNECT(server)
            if connection:
                connections[connection] = {
                    'requests': 0,
                    'responses': 0,
                    'finished_connecting': False
                }
                return True    
            else:
                print("connection failed")
        except Exception as e:
            print("987")
            print(e)
            pass
        return False


    def before_continue():
        if len(connections) < PEER_CON_LIMIT:
            make_random_connection()
        elif len(connections) == PEER_CON_LIMIT:
            prune = []
            for con in connections:
                if not con:
                    prune.append(con)
                    continue
                if connections[con]['requests'] > 30:
                    health = connections[con]['responses'] / connections[con]['requests']
                    if health < 0.5:
                        print("fd " + str(con.fileno()) + " health = " + str(connections[con]['responses'] / connections[con]['requests']) + " req: " + str(connections[con]['requests']) + " resp: " + str(connections[con]['responses'])  )
                        del connections[con]
                        break
            #catch anything that shouldn't be in there
            for x in prune:
                del connections[x]
    before_continue()
    while True:

        if len(connections) == 0:
            before_continue()
            continue 
        
        writable = []
        exceptional = []
        readable = []

        try:
            readable, writable, exceptional = select.select([*connections], writable, [*connections])
        except:
            to_dump = []
            for con in connections:
                if con.fileno() < 0:
                    to_dump.append(con)
            for con in to_dump:
                print("DUMPING connection due to negative fd")
                del connections[con]
            before_continue()
            continue

        for connection in exceptional:
            print("!!!!!!!Exceptional status on fd = " + str(connection.fileno()))
            if connection in connections:
                del connections[connection]
            before_continue()
            continue

        readable_ordered = []
        for connection in readable:
            if connections[connection]['finished_connecting']:
                readable_ordered.append(connection)

        for connection in readable:
            if not connections[connection]['finished_connecting']:
                readable_ordered.append(connection)
        

        for connection in readable:
            
            fd = connection.fileno()

            #collect the raw packet from the connection
            gen = connection.readAsync(0xffff)

            raw_packet = -1
            try:
                raw_packet = next(gen)
            except:
                pass

            if type(raw_packet) == int:
                continue            

            if not connections[connection]['finished_connecting']:
                if FINISH_CONNECTING(connection,  raw_packet):
                    connections[connection]['finished_connecting'] = True
                else:
                    try:
                        del connections[connection]
                    except:
                        pass
                continue

            if fd in partial:
                partial[fd]['message_upto'] += len(raw_packet)
                partial[fd]['message'].append(raw_packet)
                print("waiting for more data to complete message... " + str(partial[fd]['message_upto']) + "/" + str(partial[fd]['message_size']))
                if partial[fd]['message_upto'] < partial[fd]['message_size']:
                    continue
        
                #execution to here means we've finished parsing our mega packet
                raw_packet = b''.join(partial[fd]['message'])
                del partial[fd]
            
            #parse the 6 byte header which is in network byte order
            message_size = int.from_bytes(raw_packet[0:4], byteorder='big')
            message_type = int.from_bytes(raw_packet[4:6], byteorder='big')
            message_type_str = MT_TO_STR(message_type)

            if len(raw_packet) < message_size:
                partial[fd] = {
                    "message_size": message_size,
                    "message_upto": len(raw_packet) - 6,
                    "message": [raw_packet]
                }
                print("waiting for more data to complete messag on fd="+str(fd)+"e... " + str(partial[fd]['message_upto']) + "/" + str(partial[fd]['message_size']))
                continue

            #parse the message itself
            message = PARSE_MESSAGE(message_type, raw_packet[6:message_size+6])

            if not message:
                print("WARNING unreadable message")
                continue

            #check for pings and respond with a pong
            if message_type == 3: #(mtPING)
                message.type = message.ptPONG
                try: 
                    connection.send(ENCODE_MESSAGE('mtPing', message)) 
                except:
                    if connection in connections:
                        del connections[connection]
                        continue

            # these are the state xfer messages we're interested in
            if message_type == 32: #(mtLEDGER_DATA)
                if connection and connections[connection]:
                    connections[connection]['responses'] += 1

                msg_ledger_hash = tohex(message.ledgerHash)

                if not msg_ledger_hash in request_state and not message.type == ripple_pb2.TMLedgerInfoType.liTX_NODE:
                    print("1 we were sent a ledger base we didn't ask for " + tohex(msg_ledger_hash))
                    continue
                
                state = {}
                if msg_ledger_hash in state:
                    state = request_state[msg_ledger_hash]

                if message.type == ripple_pb2.TMLedgerInfoType.liBASE:
                    print("liBASE received")
                    nodeid = 0

                    for x in message.nodes:
                        print("BASE NODE " + str(nodeid))

                        ledger_hash = x.nodedata[-42:-10] # NB: this could change? we should parse this properly

                        if nodeid == 0: #can calculate ledger hash from this node
                            state["calculated_ledger_hash"] = SHA512H(b'LWR\x00' + x.nodedata)
                            state["reported_account_root_hash"] = x.nodedata[-42:-10] # NB: this could change? we should parse this properly
                            state['got_base_data'] = True
                        elif nodeid == 1:
                            state["calculated_account_root_hash"] = process_as_node(msg_ledger_hash, x, fromhex('0' * 66))

                        #print(tohex(x.nodedata))
                        nodeid += 1

                    if verify_as_nodes(state):
                        print("as node request finished")
                        fetch_acc_txs(state)

                elif message.type == ripple_pb2.TMLedgerInfoType.liTX_NODE:
                    #print("MTLEDGER NODE COUNT = " + str(len(message.nodes)))
                    affected_accounts = set()
                    for x in message.nodes:
                        #print("TX NODEID: " + tohex(x.nodeid))
                        if not x.nodedata[-1] == 4:
                            continue
        
                        #x.nodedata = decompress_node(x.nodedata)
                        h = tohex(x.nodedata)
                        txid = fromhex(h[-66:-2])
                        #print("TXID: " + tohex(txid))

                        
                        for acc in accounts:
                            if txid in accounts[acc]['wanted_tx']:
                                #print(message)
                                accounts[acc]['txseq'].add(accounts[acc]['wanted_tx'][txid]['acc_seq_no'])
                                print("REMOVED :" + tohex(txid) + " FOUND IN LEDGER " + str(message.ledgerSeq) + " ORIGINAL ESTIMATE:" + str(accounts[acc]['wanted_tx'][txid]['ledger_seq_no_at_discovery'] ))
                                affected_accounts.add(acc)
                                del accounts[acc]['wanted_tx'][txid]
                                vl = parse_vlencoded(x.nodedata[:-33])
                                print("meta:")
                                md = parse_stobject(vl[1], False)

                                if 'AffectedNodes' in md and 'ModifiedNode' in md['AffectedNodes']:
                                    modified = md['AffectedNodes']['ModifiedNode']
                                    if type(modified) != list:
                                        modified = [modified]

                                    for n in modified:
                                        #print(node['FinalFields'])
                                        if 'PreviousTxnID' in n and \
                                        'PreviousTxnLgrSeq' in n and \
                                        'FinalFields' in n and \
                                        'PreviousFields' in n and \
                                        'Account' in n['FinalFields'] and \
                                        'Sequence' in n['PreviousFields'] and \
                                        n['FinalFields']['Account'] == accounts[acc]['raw']:
                                            seq = n['PreviousFields']['Sequence'] - 1
                                            if not accounts[acc]['txseq'].contains(seq) and not n['PreviousTxnID'] in accounts[acc]['wanted_tx']:
                                                accounts[acc]['wanted_tx'][n['PreviousTxnID']] = {
                                                    "acc_seq_no": seq,
                                                    "ledger_seq_no_at_discovery": n['PreviousTxnLgrSeq'],
                                                    "max_ledger_seq_no": n['PreviousTxnLgrSeq'],
                                                    "aggression": 4
                                                } 
                                                print("Adding missing TXID to wanted:" + encode_xrpl_address(n['FinalFields']['Account']) + " prev txid " + \
                                                tohex(n['PreviousTxnID']) + " ldgseq=" + str(n['PreviousTxnLgrSeq']) + " accseq=" + \
                                                str(n['PreviousFields']['Sequence']))

                    
                    for acc in affected_accounts:
                        print(acc + ": " + str(accounts[acc]['txseq']))
                        #print("nodelen: " + str(len(x.nodedata)))
                 #       vl = parse_vlencoded(x.nodedata[:-33])
                        #print("tx proper:")
                 #       tx = parse_stobject(vl[0], False)
                        #print("meta:")
                 #       md = parse_stobject(vl[1], False)

    #                    #parse_stobject(x.nodedata[2:-33], True)

                        
                        #d = tohex(x.nodedata)
                        #print(d)
                        #offset = 2
                        #for i in range(0, 16):
                        #    print("hash " + str(i) + ":" + d[i*64 + offset:(i+1)*64 + offset])

                        
                        #for y in parse_vlencoded(x.nodedata[:-33]):
                        #    parse_stobject(y, True) 


                elif message.type == ripple_pb2.TMLedgerInfoType.liAS_NODE:
                    print("liAS_NODE")
                    for x in message.nodes:
                        process_as_node(msg_ledger_hash, x)

                    if verify_as_nodes(state):
                        fetch_acc_txs(state)
                        print("as node request finished")

            if message_type == 42: #GetObjectByHash
                pass
                #print('get object by hash: -------')
                #print(message)
                #print('-----------')

            if message_type == 30: #Transaction
                #wait for at least one validation before we start wanting tx
                if last_ledger_seq_no == -1:
                    continue

                
                #print('mtTransaction: ' + tohex(SHA512HP(b'TXN\x00', message.rawTransaction))
                

                # filter cheaply before parsing 
                found = False
                for acc in accounts:
                    if message.rawTransaction.find(accounts[acc]['raw']):
                        found = True
                        break

                if not found:
                    continue

                tx = parse_stobject(message.rawTransaction, False)
                 
                if tx:
                    for acc in accounts:
                        if accounts[acc]['raw'] == tx['Account'] or 'Destination' in tx and accounts[acc]['raw'] == tx['Destination']:

                            txid = SHA512HP(b'TXN\x00', message.rawTransaction)
                            if txid in accounts[acc]['wanted_tx']:
                                break

                            seq = tx['Sequence']
                            if int(tohex(txid[0:2]), 16) % 20 == 0 or \
                            int(tohex(txid[0:2]), 16) % 20 == 1 or \
                            int(tohex(txid[0:2]), 16) % 20 == 2:
                                print("dropping tx " + tohex(txid) + " for testing, seq=" + str(seq))
                                continue 

                            if 'Destination' in tx and accounts[acc]['raw'] == tx['Destination']:
                                seq = 0xFFFFFFFF

                            accounts[acc]['wanted_tx'][txid] = {
                                "acc_seq_no": tx['Sequence'],
                                "ledger_seq_no_at_discovery": last_ledger_seq_no,
                                "max_ledger_seq_no": tx['LastLedgerSequence'],
                                "aggression": 3
                            }
                            print('TX: ' + encode_xrpl_address(tx['Account']) + "[W"+str(len(accounts[acc]['wanted_tx']))+" D"+str(len(accounts[acc]['dropped_tx']))+"]" + ", " + str(tx['Sequence']) + " {" + str(last_ledger_seq_no) + "}  " + tohex(txid))
                            break
        
            if message_type == 15: #(mtEndpoints)
                #print('mtEndpoints')
                new_ips = set()
                for endpoint in message.endpoints_v2:
                    ip = endpoint.endpoint.replace('[::', '').replace('ffff:', '').replace(']', '')
                    if re.match(r'^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}$', ip) != None:
                        if not ip in peers:
                            peers.add(ip)
                            new_ips.add(ip)
                #f = open(peer_file, "a+")
                #if f:
                #    for ip in new_ips:
                #        #print("wrote " + ip)
                #        f.write(ip + "\n")
                #    f.close()
                #print(message)
            

            if message_type == 41: #(mtVALIDATION)
                #todo check if validations are from our selected UNL
                sto = parse_stobject(message.validation, False)#True)

                ledger_hash = sto['LedgerHash']
                ledger_seq = sto['LedgerSequence'] # int(message.validation.hex()[12:20], 16) #todo change this to pull from sto
                
                signing_key = sto['SigningPubKey']

                if not ledger_hash in validations:
                    validations[ledger_hash] = {}

                to_prune = []
                for x in validations:
                    for y in validations[x]:
                        if validations[x][y] <= ledger_seq - 5:
                            to_prune.append(x)
                            break

                for x in to_prune:
                    del validations[x]
    

                #todo: check validation signature
                if signing_key in UNL and not signing_key in validations[ledger_hash]:
                    validations[ledger_hash][signing_key] = ledger_seq
               

                #print(tohex(message.validation))

                #print( "PK in UNL? " + str( (signing_key in UNL) ) )

                if len(validations[ledger_hash]) < len(UNL) * 0.8:
                    continue
                

                # execution to here indicates the ledger is validated and we want to make our request now
                #time.sleep(4) #ensure everyone has the ledger on file


                if last_ledger_seq_no >= ledger_seq:
                    continue

                last_ledger_seq_no = ledger_seq
            
                print("mtVALIDATION ... " + str(len(validations[ledger_hash])) + "/" + str(len(UNL)) + " UNL peers have validated - ledger = " + str(ledger_seq))
                request_wanted_tx()

                continue
        
                print("requesting ledger " + str(ledger_seq) + " hash = " + tohex(ledger_hash)) 
                # first request the base ledger info
                gl = ripple_pb2.TMGetLedger()
                gl.ledgerHash = ledger_hash
                gl.ledgerSeq = ledger_seq
                gl.queryDepth = 1
                gl.itype = ripple_pb2.TMLedgerInfoType.liBASE
                send_rand_peer(ENCODE_MESSAGE('mtGetLedger', gl))
                #requested_ledgers[ledger_hash] = TIME()
                
                state = new_state()
                request_state[ledger_hash] = state

                state['requested_ledger_hash'] = ledger_hash    

                for acc in accounts:
                    requested_node = accounts[acc]['asroot_key']

                    print('requesting node: ' + requested_node)
                    # now request the account state info
                    gl = ripple_pb2.TMGetLedger()
                    gl.ledgerHash = ledger_hash
                    gl.ledgerSeq = ledger_seq
                    gl.itype = ripple_pb2.TMLedgerInfoType.liAS_NODE
                   
                    for l in range(1, len(requested_node)):
                        v = hex(l)[2:]
                        key = requested_node[0:l] + ('0' * (66 - l - len(v))) + v
                        gl.nodeIDs.append(fromhex(key))

                    gl.queryDepth = 0
                    send_rand_peer(ENCODE_MESSAGE('mtGetLedger', gl))
                
        before_continue()
        continue    
    return state

# process commandline
if len(argv) == 0:
    print("usage: " + sys.argv[0] + " rSomeAccountToWatch rSomeOtherAccountToWatch ...")
    quit()

binprefix = b'\x00a'
if type(binprefix) == str: #leave this here in case we change the way binprefix is provided later
    binprefix = fromhex(binprefix)

for raccount in argv:
    acc = raccount
    
    if raccount != False and type(raccount) == str:
        if raccount[0] == 'r':
            raccount = decode_xrpl_address(raccount)
        else:
            raccount = fromhex(raccount)
    
    asroot_key = ''
    if raccount != False:
        asroot_key = SHA512H(binprefix + raccount).hex() 
    else:
        asroot_key = SHA512H(binprefix).hex() 


    accounts[acc] = {
        "raw": raccount, 
        "asroot_key": asroot_key, #asroot
        "wanted_tx": {}, # txid->seqno
        "dropped_tx": [] #txid
    }
    if not os.path.exists(acc):
        os.mkdir(acc)

    if not os.path.exists(acc + '/tx'):
        os.mkdir(acc + '/tx')

    if not os.path.exists(acc + '/txseq.txt'):
        IntervalSet().save(acc + '/txseq.txt')

    accounts[acc]['txseq'] = IntervalSet(acc + '/txseq.txt')


# build UNL from the validator site specified, if any
if type(validator_site) == str and len(validator_site) > 0:
    context = ssl._create_unverified_context()
    vl = urllib.request.urlopen(validator_site,  context=context).read().decode('utf-8')
    vl = json.loads(vl)
    if vl['public_key'].upper() != 'ED2677ABFFD1B33AC6FBC3062B71F1E8397C1505E1C42C64D11AD1B28FF73F4734':
        print("attempted to fetch validator list from " + validator_site + " but found unknown list signing key!")
        exit(1)
    #todo: check validator list signature here

    payload = json.loads(base64.b64decode(vl['blob']))
    st = base64.b64decode(payload['validators'][0]['manifest'])
    for v in payload['validators']:
        #todo: check signatures of each validator here
        sto = parse_stobject(base64.b64decode(v['manifest']))
        UNL.append(sto['SigningPubKey']) 

    print("Loaded a UNL from validator site " + validator_site + " consisting of " + str(len(UNL)) + " validators")

REQUEST_LOOP()

exit() 
