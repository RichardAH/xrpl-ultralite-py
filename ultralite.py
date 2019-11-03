# XRPL UltraLite
#   Author: Richard Holland

#change this to localhost if you want to connect to your own node
#todo: add a peer list that is updated when connecting
#todo: add UNL
server = "202.177.24.140" #"s.altnet.rippletest.net"
port = 51235 

from ecdsa import SigningKey, SECP256k1
from base58r import base58r
from serializer import serializer
from socket import *
from stlookup import *
import ripple_pb2
import binascii
import operator
import tlslite
import hashlib
import base64
import ecdsa
import time
import json
import re
import math
import time

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
    return SHA512(b''.join([p, b]))

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
    return 0

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

def parse_stobject(x, print_out = False):

    sto = {}

    upto = 0
    while upto < len(x):
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
            return False

        if print_out:
            print(STLookup[typecode][fieldcode]['field_name'] + ": ", end='')

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
        else:
            print("warning could not determine size of stobject")
            return False
                

        if is_amount and size == 8:
            val = int(str(binascii.hexlify(x[upto:upto+size]), 'utf-8'), 16) - 0x4000000000000000
            sto[fieldname] = {"currency": "xrp",  "value": val}
            if print_out:
                print ("XRP " + str(val/1000000))
        elif is_amount:

            #print("RAW AMOUNT DATA: " + str(binascii.hexlify(x[upto:upto+384]), 'utf-8'))

            curcode = str(x[upto+20:upto+23], 'utf-8')

            amount = 0
            if x[upto:upto+8] != b'\x80\x00\x00\x00\x00\x00\x00\x00':
                #do the amount math since it's not the special zero case
                # first 10 bits are flags and expontent, final 54 are mantissa
                mantissa = int(str(binascii.hexlify(x[upto+1:upto+8]), 'utf-8'), 16)
                # the two msb of mantissa are bleedover from exponent
                # probably should have assembled the value byte by byte instead of doing this
                if mantissa >= 0x8000000:
                    mantissa -= 0x8000000
                if mantissa >= 0x4000000:
                    mantissa -= 0x4000000

                exponent = int(str(binascii.hexlify(x[upto:upto+2]), 'utf-8'), 16)
                exponent >>= 6
                exponent &= 0xFF
               
                # as per spec we need to sub 97 from exponent now 
                exponent -= 97

                sign = (x[upto] >> 7) & 1     
            
                amount = mantissa * 10 ** exponent
                

            issuer = x[upto+28:upto+48]

            sto[fieldname] = {"currency": curcode,  "value": amount, "issuer": issuer}
            
            if print_out:
                print (curcode + ": " + str(amount) + " [Issuer:" + str(binascii.hexlify(issuer), 'utf-8') + "]")

        elif size <= 8:
            val = int(str(binascii.hexlify(x[upto:upto+size]), 'utf-8'), 16)
            sto[fieldname] = val
            if print_out:
                if 'flags' in STLookup[typecode][fieldcode]['field_name'].lower():
                    print( "{0:b}".format(val) )
                else:
                    print(val)
        else:
            if print_out:
                print( str(binascii.hexlify(x[upto:upto+size]), 'utf-8'))
            sto[fieldname] = x[upto:upto+size]

        upto += size


def CONNECT(server, port):            
    print("Attempting to connect to " + server + " : " + str(port))
    #generate a node key
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()

    #node key must be in compressed form (x-coord only) and start with magic type 0x1C
    order = ecdsa.SECP256k1.generator.order()
    point = vk.pubkey.point
    x = (b'\x1c\x02', b'\x1c\x03')[point.y() & 1] + ecdsa.util.number_to_string(point.x(), order)
    y = SHA256CHK(x) #checksum bytes
    x += y

    #encode node key into standard base58 notation using the ripple alphabet
    b58pk = base58r.b58encode(x).decode('utf-8')

    #open the socket
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect( (server, port) )

    #attach the tls class  /  this tls lib has been modified to expose the finished messages for use in the rippled cookie
    connection = tlslite.TLSConnection(sock)
    connection.handshakeClientCert()

    #extract and calculate message hashes
    cookie1 = SHA512(connection.remoteLastMessage())
    cookie2 = SHA512(connection.localLastMessage())
    cookie = SHA512H(XOR(cookie1, cookie2))

    #the cookie must be signed with our private key
    sig = base64.b64encode(sk.sign_digest(cookie, sigencode=ecdsa.util.sigencode_der)).decode('utf-8')

    #finally construct the GET request which will allow us to say hello to the rippled server
    request =  'GET / HTTP/1.1\r\n'
    request += 'User-Agent: rippled-1.3.1\r\n'
    request += 'Upgrade: RTXP/1.2\r\n'
    request += 'Connection: Upgrade\r\n'
    request += 'Connect-As: Peer\r\n'
    request += 'Crawl: private\r\n'
    request += 'Session-Signature: '+sig+'\r\n'
    request += 'Public-Key: '+b58pk+'\r\n\r\n'

    #send the request
    connection.send(bytes(request, 'utf-8'))

    #the first packet will still be http
    packet = connection.recv(1024).decode('utf-8')

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
                    parts = x.split(":")
                    port = int(parts[1], 10)
                    server = parts[0]
                    return CONNECT(server, port)
  
        else:
            print("Failed to connected, received:")
            print(packet)
       
     
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
def REQUEST_AS(connection, binprefix, raccount = False):

    if raccount != False and type(raccount) == str:
        if raccount[0] == 'r':
            raccount = serializer.decode_address(raccount)
        else:
            raccount = binascii.unhexlify(raccount)
    
    if type(binprefix) == str:
        binprefix = binascii.unhexlify(binprefix)


    requested_node = ''
    if raccount != False:
        requested_node = SHA512H(binprefix + raccount).hex() 
    else:
        requested_node = SHA512H(binprefix).hex() 


    # data may come in asynchronously
    # so we collect it all first and then compute at the end
    state = {
        "proven_correct": False, #indicates all the hashes have been checked up the tree
        "requested_ledger_hash": False,
        "calculated_ledger_hash": False,
        "reported_account_root_hash": False,
        "calculated_account_root_hash": False,
        "account_depth": False,
        "account_key": False,
        "account_path_nodes": {} #these are the inner nodes that lead down to the account, including root, indexed by depth
    }

    got_base_data = False
    got_account_data = False


    def check_if_done():
        #return False

        if got_base_data and got_account_data:
            # check the hashes, if any don't match we'll return early with the default proven_correct value (False)
            if state["requested_ledger_hash"] != state["calculated_ledger_hash"]:
                print("requested ledger doesn't match calculated ledger")
                return True

            if state["reported_account_root_hash"] != state["calculated_account_root_hash"]:
                print("account root hash doesn't match")
                return True

            if state["account_depth"] + 1 != len(state["account_path_nodes"]):
                print("account depth doesn't match / missing inner nodes")
                return True

            #this helper function will test each of the possible branches of an inner node against a searched for hash
            def node_contains(node, findhash):
                for n in range(0, 512, 32):
                    if node[n:n+32] == findhash:
                        #print("Found " + str(binascii.hexlify(findhash),'utf-8') + " at branch " + str(n/32))
                        return True
                return False      

            
            #compute up the tree now
            for i in range(state['account_depth'], 0, -1):
                computed_hash = b''
                if i == state['account_depth']: #leaf node is computed with MLN\0 not MIN\0
                    computed_hash = SHA512H(b'MLN\x00' + state['account_path_nodes'][i][:-1])
                else:
                    computed_hash = SHA512H(b'MIN\x00' + state['account_path_nodes'][i][:-1])
                if not node_contains(state['account_path_nodes'][i-1], computed_hash):
                    print("inner node at depth " + str(i) + " computed hash " + str(binascii.hexlify(computed_hash), 'utf-8') + " wasn't found in the node above")
                    return True

            state["proven_correct"] = True 
            return True

        return False


    def process_as_node(x, nodeid = False):
        nonlocal got_account_data

        nodetype = x.nodedata[-1]
        if hasattr(x, 'nodeid') and nodeid == False:
                nodeid = x.nodeid
        depth = nodeid[-1]
        nodehash = False

        if nodetype == 3: # inner node, compressed wire format, decompress...
            blank_branch = binascii.unhexlify('0' * 64)
            reconstructed_node = b''
            upto = 0
            for branch in range(0, 16):
                if upto + 32 < len(x.nodedata) and x.nodedata[upto + 32] == branch:
                    reconstructed_node += x.nodedata[upto:upto+32]
                    upto += 33
                else:
                    reconstructed_node += blank_branch
           
            reconstructed_node += b'\x02'
            x.nodedata = reconstructed_node
            state["account_path_nodes"][depth] = reconstructed_node
            nodetype = 2
       
        # execution to here means it's either a leaf or uncompressed 
        
        nodehash = SHA512H(b'MIN\x00' + x.nodedata[:-1])
        state["account_path_nodes"][depth] = x.nodedata
        
        print("AS KEY: " + nodeid.hex())

        if nodetype == 1: # leaf node, wire format
            #this is our sought after account
            nodehash = SHA512H(b'MLN\x00' + x.nodedata[:-1])
            state["account_key"] = nodeid
            state["account_depth"] = nodeid[-1]
            state["reported_account_hash"] = x.nodedata[-33:-1]
            print("FOUND: " + str(binascii.hexlify(state["reported_account_hash"]), 'utf-8'))
            parse_stobject(x.nodedata[:-33], True)
            got_account_data = True
            

        elif nodetype != 2: # inner node, compressed, wire format
            print("UNKNOWN NODE " + str(nodetype))


        return nodehash 

    
    last_requested_ledger = ""
    
    partial_message = []
    partial_message_size = 0
    partial_message_upto = 0

    sent_request = False


    #message loop
    while True:

        #collect the raw packet from the connection
        raw_packet = connection.recv(0xffff)

        if partial_message_size > 0:
            partial_message_upto += len(raw_packet)
            partial_message.append(raw_packet)
            print("waiting for more data to complete message... " + str(partial_message_upto) + "/" + str(partial_message_size))
            if partial_message_upto < partial_message_size:
                continue
    
            #execution to here means we've finished parsing our mega packet
            raw_packet = b''.join(partial_message)
            partial_message = []
            partial_message_size = 0
            partial_message_upto = 0
        
        #parse the 6 byte header which is in network byte order
        message_size = int.from_bytes(raw_packet[0:4], byteorder='big')
        message_type = int.from_bytes(raw_packet[4:6], byteorder='big')
        message_type_str = MT_TO_STR(message_type)

        if len(raw_packet) < message_size:
            partial_message_size = message_size
            partial_message_upto = len(raw_packet) - 6
            print("waiting for more data to complete message... " + str(partial_message_upto) + "/" + str(partial_message_size))
            partial_message.append(raw_packet)
            continue

        #parse the message itself
        message = PARSE_MESSAGE(message_type, raw_packet[6:message_size+6])

        #check for pings and respond with a pong
        if message_type == 3: #(mtPING)
            message.type = message.ptPONG 
            connection.send(ENCODE_MESSAGE('mtPing', message)) 

        # these are the state xfer messages we're interested in
        if message_type == 32: #(mtLEDGER_DATA)
            print("mtLEDGER_DATA:")
            if message.type == ripple_pb2.TMLedgerInfoType.liBASE:
                print("liBASE received")
                nodeid = 0
                for x in message.nodes:
                    #print("BASE NODE " + str(nodeid))
                    if nodeid == 0: #can calculate ledger hash from this node
                        state["calculated_ledger_hash"] = SHA512H(b'LWR\x00' + x.nodedata)
                        state["reported_account_root_hash"] = x.nodedata[-42:-10] # NB: this could change? we should parse this properly
                        got_base_data = True
                    elif nodeid == 1:
                        state["calculated_account_root_hash"] = process_as_node(x, binascii.unhexlify('0' * 66))

                    #print(binascii.hexlify(x.nodedata))
                    nodeid += 1

                if check_if_done():
                    return state

                if got_account_data:
                    print("could not find base data")
                    return state

            elif message.type == ripple_pb2.TMLedgerInfoType.liTX_NODE:
                for x in message.nodes:
                    print("TX NODEID: " + str(binascii.hexlify(x.nodeid)))
                    #print("NODEDATA: " + str(binascii.hexlify(x.nodedata)))
                    if x.nodedata[-1] == 1:
                        parse_stobject(x.nodedata[:-33], True)

            elif message.type == ripple_pb2.TMLedgerInfoType.liAS_NODE:
                print("liAS_NODE")
                for x in message.nodes:
                    process_as_node(x)

                if check_if_done():
                    return state

                if got_base_data:
                    print("could not find requested object")
                    return state
                

        if message_type == 42: #GetObjectByHash
            print('get object by hash: -------')
            print(message)
            print('-----------')


        if message_type == 41: #(mtVALIDATION)
            #todo check if validations are from our selected UNL

            ledger_hash = message.validation[16:48] #todo: parse this properly

            if sent_request:
                continue        

            sent_request = True

            
            print("mtVALIDATION:")

            validation = parse_stobject(message.validation, True)

            state["requested_ledger_hash"] = message.validation[16:48] #todo pull this correctly from the object above

            time.sleep(4)
            
            ledger_seq = int(message.validation.hex()[12:20], 16)

            # first request the base ledger info
            gl = ripple_pb2.TMGetLedger()
            gl.ledgerHash = ledger_hash
            gl.ledgerSeq = ledger_seq
            gl.queryDepth = 1
            gl.itype = ripple_pb2.TMLedgerInfoType.liBASE
            connection.send(ENCODE_MESSAGE('mtGetLedger', gl))

            #liTX_NODE
           
            if False:
                gl = ripple_pb2.TMGetLedger()
                gl.ledgerHash = ledger_hash
                gl.ledgerSeq = ledger_seq
                gl.itype = ripple_pb2.TMLedgerInfoType.liTX_NODE
           
                #request the root account
                gl.nodeIDs.append(binascii.unhexlify('0' * 66))
            
                gl.queryDepth = 2
                connection.send(ENCODE_MESSAGE('mtGetLedger', gl))
                continue
 
            # now request the account state info
            gl = ripple_pb2.TMGetLedger()
            gl.ledgerHash = ledger_hash
            gl.ledgerSeq = ledger_seq
            gl.itype = ripple_pb2.TMLedgerInfoType.liAS_NODE
           
            for l in range(1, len(requested_node)):
                v = hex(l)[2:]
                key = requested_node[0:l] + ('0' * (66 - l - len(v))) + v
                gl.nodeIDs.append(binascii.unhexlify(key))

            gl.queryDepth = 0
            connection.send(ENCODE_MESSAGE('mtGetLedger', gl))

    return state

connection = CONNECT(server, port)

if connection == False:
    print("could not connect!")
    quit()

data = REQUEST_AS(connection, b'\x00O', 'rToastMYRQh8boeo5Ys1CnPySmt3c9x3Y')

if not data['proven_correct']:
    print("Unable to verify data authenticity")
else:
    print("object verified")

exit() 
