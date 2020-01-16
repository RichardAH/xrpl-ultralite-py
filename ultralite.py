# XRPL UltraLite
#   Author: Richard Holland
# Todo: remove bad peers after X failed connections
config = {
    #---stuff you will want to configure is immediately below
    "connection_limit": 2, # maximum number of simulatenous peer connections to maintain
    "allow_write_to_peer_file": True, # you most likely want to change this to false if you run on an embedded device
    "write_to_stdout": False, # if True metadata will be written on stdout
    "write_to_file": True, # if True metadata will be written to ./<raccount>/tx/<txid> 
    #--- you probably don't want to change anything under this point
    "DEBUG": True,
    "bootstrap_server": "s1.ripple.com:51235", #this will be connected to if no peers are currently available from the peer file
    #"full_history_peers": ["s2.ripple.com"], # we will use these to backfill our transaction history (in a later version)
    "UNL": [], #if blank we populate from the validator site specified below
    "validator_site": "https://vl.ripple.com",
    "peer_file": "peers.txt",
    "manifest_master_public_key": "ed2677abffd1b33ac6fbc3062b71f1e8397c1505e1c42c64d11ad1b28ff73f4734" #this is the key whose manfiests you will accept
}

#------------- end config



# print to stderr if debug is on or override is specified
def dprint(text, override_default = False):
    if config['DEBUG'] or override_default:
        sys.stderr.write(str(datetime.now()).split(".")[0] + ": " + str(text) + "\n")


import sys
import signal
from datetime import datetime
dprint("[INF IM] Loading imports, including NACL, this may take a while or hang if you have low entropy on your system/device...")
import traceback
import time
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
import nacl.signing
import nacl.encoding
import os
import fastecdsa.encoding
import fastecdsa.encoding.der
import fastecdsa.encoding.sec1
import fastecdsa.curve
import fastecdsa.ecdsa
import threading
from util import *
dprint("[INF IM] All imports loaded!")

WRITE_LOCK = threading.Lock()

def die(retcode):
    sys.stdout.flush()
    
    os._exit(retcode)

def sigterm_handler(_signo, _stack_frame):
    dprint("[SIG TM] Termination signal received, flushing buffers, bye!")
    WRITE_LOCK.acquire()
    die(0)

signal.signal(signal.SIGTERM, sigterm_handler)
signal.signal(signal.SIGINT, sigterm_handler)

class xrpl_ultralite:

    ledger_chain = {} # ledger_hash -> { prev_ledger_hash: , seq_no: , account_root: , tx_root: , root: }
    ledger_seq = {} # ledger_seqno -> ledger_hash
    last_ledger_seq_verified = False # contains the head of the verified ledger chain
    first_ledger_seq_verified = False # contains the fail of the verified ledger chain
    last_ledger_hash_verified = False # contains the head of the verified ledger chain
    first_ledger_hash_verified = False # contains the fail of the verified ledger chain

    wanted_ledgers = {} # wanted ledger seq no -> ledger hash or False
    tx_waiting_on_ledgers = {} # wanted ledger seq -> txid -> { "proof": proof_nodes, "nodedata": x.nodedata, 'acc': acc } 
    ac_waiting_on_ledgers = {} # wanted ledger seq -> acc -> { "proof": , "nodedata": }

    ledgers_waiting_on_ledgers = {} # wanted ledger hash -> legder has to reprocess for tx once wanted ledger is received

    last_missing_msg = "" # used to supress missing repeating message output

    accounts = {}
    peers = set()
    connections = {}

    last_ledger_seq_seen = -1
    last_ledger_hash_seen = False


    node_sk = ""
    node_vk = ""
    node_b58pk = ""
    config = None

    
    def __init__(self, config):
        self.config = config
        
        argv = sys.argv[1:]
        
        # process commandline
        if len(argv) == 0:
            dprint("[INF CL] Usage " + sys.argv[0] + " rSomeAccountToWatch rSomeOtherAccountToWatch ...", True)
            quit()

        #generate a node key
        self.node_sk = SigningKey.generate(curve=SECP256k1)
        self.node_vk = self.node_sk.get_verifying_key()
        #node key must be in compressed form (x-coord only) and start with magic type 0x1C
        order = ecdsa.SECP256k1.generator.order()
        point = self.node_vk.pubkey.point
        x = (b'\x1c\x02', b'\x1c\x03')[point.y() & 1] + ecdsa.util.number_to_string(point.x(), order)
        y = SHA256CHK(x) #checksum bytes
        x += y
        #encode node key into standard base58 notation using the ripple alphabet
        self.node_b58pk = base58r.b58encode(x).decode('utf-8')

        x = None
        y = None

        WRITE_LOCK.acquire()
        f = open(self.config['peer_file'], "r+")
        if f:
            content = f.readlines()
            f.close()
            for ip in content:
                self.peers.add(ip)
        else:
            dprint("[ERR FS] Could not open peer file for reading and writing " + self.config['peer_file'])
        WRITE_LOCK.release()

        self.peers.add(config['bootstrap_server'])
 
        # build UNL from the validator site specified, if any
        if len(self.config['UNL']) > 0:
            for x in self.config['UNL']:
                if len(x) != 33 or type(x) != bytes:
                    dprint("[ERR VL] Invalid UNL specified, keys should be 33 bytes and of type bytes")
                    quit()
        elif type(self.config['validator_site']) == str and len(self.config['validator_site']) > 0:
            dprint("[INF VL] Loading manifest from validator site " + self.config['validator_site'])
            context = ssl._create_unverified_context()
            vl = urllib.request.urlopen(config['validator_site'],  context=context).read().decode('utf-8')
            vl = json.loads(vl)
            if vl['public_key'].lower() != config['manifest_master_public_key']:
                dprint("[INF VL] Attempted to fetch validator list from " + self.config['validator_site'] + " but found unknown list signing key!")
                die(1)

            if 'signature' in vl and 'public_key' in vl and 'blob' in vl and 'manifest' in vl or len(vl['public_key']) != 33 or lower(vl['public_key'][0:2]) != 'ed':
                pass
            else:
                dprint("[ERR VL] Validator list site returned invalid format", True)
                die(1)

            rawmanifest = base64.b64decode(vl['manifest'])
            manifest = parse_stobject(base64.b64decode(vl['manifest']), False, False)
            
            masterkey = from_hex(config['manifest_master_public_key'])#vl['public_key'])#[1:]
            
            mastersig = manifest['MasterSignature']

            signingkey = manifest['SigningPubKey']

            payload = base64.b64decode(vl['blob'])
            manifest = base64.b64decode(vl['manifest'])
            signature = from_hex(vl['signature'])
            
            dprint("[INF MN] Master key " + to_hex(masterkey))
            dprint("[INF MN] Signing key " + to_hex(signingkey))

            # the manifest needs to be recast without signing fields, in order to be verified
            # the form of the stobject is generic but starts with a 32bit int 'M' 'A' 'N' '\x00'
            # we don't have a full STObject builder so we're just going to do some byte manipulation to get the existing binary into this form
            # the length of the manifest st object with no signature feilds is 75, this shouldn't change

            sigfreemanifest = b'MAN\x00' + rawmanifest[:75] 
            verify_master_key = nacl.signing.VerifyKey(masterkey[1:])
           # print("verification - 1: " + to_hex(verify_master_key.verify(sigfreemanifest, mastersig)))
            try:
                verify_master_key.verify(sigfreemanifest, mastersig)
            except:
                dprint("[ERR MN] Manifest signature verification failed", True)
                die(1)

            # execution to here means manifest was signed correctly by master key
            dprint("[INF MN] Manifest signature successfully verified against master key")

            # check payload signature
            payload_signature = from_hex(vl['signature'])
            verify_signing_key = nacl.signing.VerifyKey(signingkey[1:])
            try:
                verify_signing_key.verify(payload, payload_signature)
            except:
                dprint("[ERR VL] Validator list signature verification failed", True)
                die(1)

            # execution to here means the validator list payload was correctly signed against the trust chain

            #todo: verify signing key is validly structured
            #todo: check sequence number and revocations

            # now parse the payload and check every signature before adding each validator to the UNL
            payload = json.loads(payload)
            st = base64.b64decode(payload['validators'][0]['manifest'])
            for v in payload['validators']:
                rawmanifest = base64.b64decode(v['manifest'])
                sto = parse_stobject(rawmanifest, False, False)
                verify_signing_key = nacl.signing.VerifyKey(sto['PublicKey'][1:])
                sigfreemanifest = b'MAN\x00' + rawmanifest[:75]
                try:
                    verify_signing_key.verify(sigfreemanifest, sto['MasterSignature'])
                except Exception as e:
                    dprint("[ERR MN] Validator " + to_hex(sto['PublicKey']) + "manifest signature verification failed", True)
                    die(1)

                self.config['UNL'].append(sto['SigningPubKey']) 

            dprint("[INF VL] Successfully loaded " + str(len(self.config['UNL'])) + " validators")
        else:
            dprint("[ERR VL] You must specified either a UNL or a validator list site", True)
            quit()


        binprefix = b'\x00a'
        if type(binprefix) == str: #leave this here in case we change the way binprefix is provided later
            binprefix = from_hex(binprefix)

        for raccount in argv:
            acc = raccount
            if acc[-1] == '/':
                acc = acc[:-1] 
            if raccount != False and type(raccount) == str:
                if raccount[0] == 'r':
                    if raccount[-1] == '/': # this is because often you'll just hit tab at commandline to fill the rAccount parameter
                        raccount = raccount[:-1]
                    raccount = decode_xrpl_address(raccount)
                else:
                    raccount = from_hex(raccount)
            
            asroot_key = ''
            if raccount != False:
                asroot_key = SHA512H(binprefix + raccount).hex() 
            else:
                asroot_key = SHA512H(binprefix).hex() 


            self.accounts[acc] = {
                "raw": raccount, 
                "asroot_key": asroot_key, #asroot
                "asroot_key_raw": from_hex(asroot_key), #asroot
                "wanted_tx": {}, # txid->seqno
                "tx_chain": {}, # next txid -> previous tx
                "tx_ledger_seq": {}, #txid -> ledgerseq
                "tx_first": None,
                "tx_first_fsi": 0xffffffffffffffff, #first seen index is a 64bit number comprising ledgerSeq << 32 + transaction seq within that ledger
                "tx_last": None, #most recent tx affecting this account that we've received metadata for
                "tx_last_lsi": 0, #last seen index is a 64bit number comprising ledgerSeq << 32 + transaction seq within that ledger
                "tx_chain_valid_to": None, # the txid the chain has been checked for continuity
                "dropped_tx": [] #txid
            }
            if not os.path.exists(acc):
                os.mkdir(acc)

            if not os.path.exists(acc + '/tx'):
                os.mkdir(acc + '/tx')

    def write_peer_file(self):
        WRITE_LOCK.acquire()
        f = open(self.config['peer_file'], "w")
        if f:
            for ip in self.peers:
                f.write(ip + "\n")
            f.close()
        else:
            dprint("[ERR FS] Could not open peer file for writing " + self.config['peer_file'])
        WRITE_LOCK.release()

    def connect(self, server):
        server = server.replace("\r", "").replace("\n", "")       
        dprint("[TRY CX] EXISTING CONNECTIONS = " + str(len(self.connections)) + "\t Now attempting connection to " + server )
        
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
        sig = base64.b64encode(self.node_sk.sign_digest(cookie, sigencode=ecdsa.util.sigencode_der)).decode('utf-8')

        #finally construct the GET request which will allow us to say hello to the rippled server
        request =  'GET / HTTP/1.1\r\n'
        request += 'User-Agent: rippled-1.3.1\r\n'
        request += 'Upgrade: RTXP/1.2\r\n'
        request += 'Connection: Upgrade\r\n'
        request += 'Connect-As: Peer\r\n'
        request += 'Crawl: private\r\n'
        request += 'Session-Signature: ' + sig + '\r\n'
        request += 'Public-Key: ' + self.node_b58pk + '\r\n\r\n'

        #send the request
        connection.send(bytes(request, 'utf-8'))
        return connection

    def finish_connecting(self, connection,  packet):
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
                        if not x in self.peers:
                            self.peers.add(x)
                        return False

                if len(peer_ips) > 0:
                    if self.config['allow_write_to_peer_file']:
                        self.write_peer_file()
      
            else:
                #dprint("Failed to connected, received:")
                #dprint(packet)
                pass
           
            #dprint("failed") 
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
                    #dprint("node version: " + server_version) 
                elif ph[0] == "Public-Key":
                    server_key = ph[1]
                    #dprint("node key: " + server_key)
                elif ph[0] == "Closed-Ledger":
                    server_closed_ledger = ph[1]
                    #dprint("last closed ledger: " + server_closed_ledger)
                elif ph[0] == "Crawl":
                    server_private = ph[1] == "private" 
                    #dprint("server is " + ("private" if server_private else "public"))

        #NB: execution to this point means the connection was successful
        return connection




    def check_ledger_chain(self, ledgerSeq, ledgerHash):
        # before we process, we need to ensure there is a complete chain from lcl back to the ledger
        # this tx appeared in   

        if self.last_ledger_hash_verified == False:
            #dprint("can't check ledger chain until some ledgers have been received")
            return False

        if ledgerSeq > self.last_ledger_seq_verified:
            dprint("[INF LG] can't check ledger chain because trying to check newer ledger "+str(ledgerSeq)+" than newest in chain " + str(self.last_ledger_seq_verified))
            return False
        
        if ledgerSeq < self.first_ledger_seq_verified:
            dprint("[INF LG] can't check ledger chain because trying to check older ledger "+str(ledgerSeq)+" than oldest in chain " + str(self.last_ledger_seq_verified))
            return False

        ledger_is_missing = False
        for ls in range(self.first_ledger_seq_verified, self.last_ledger_seq_verified, 1):
            if not ls in self.ledger_seq:
                if not ls in self.wanted_ledgers:
                    #dprint("added " + str(ls) + " to wanted ledgers list")
                    self.wanted_ledgers[ls] = False
                    if ledgerSeq == ls:
                        ledger_is_missing = True

        if ledger_is_missing:
            dprint("[INF LG] can't check ledger chain because ledger we're checking against " + str(ledgerSeq) + " is missing")
            return False
    
        # execution to here means nominally we have all the ledgers we need to make the check, so now check hashes

        p = self.ledger_chain[self.last_ledger_hash_verified]['prev_ledger_hash']
        while p in self.ledger_chain:
            if p == ledgerHash:
                break
            p = self.ledger_chain[p]['prev_ledger_hash']

        if p != ledgerHash:
            if p in self.ledgers_waiting_on_ledgers:
                self.ledgers_waiting_on_ledgers[p].add(ledgerHash)
            else:
                self.ledgers_waiting_on_ledgers[p] = set(ledgerHash)
        #    dprint("check ledger chain failed " + to_hex(p) + " != " + to_hex(ledgerHash))
            return False

        return True


    def verify_node_proof(self, proof, inner_prefix, leaf_prefix):
        #compute up the tree 
        for i in range(len(proof) - 1, 1, -1):
            computed_hash = b''
            if i == len(proof) - 1: #leaf node is computed with SND\0 not MIN\0
                computed_hash = SHA512H(leaf_prefix + proof[i][:-1])
            else:
                computed_hash = SHA512H(inner_prefix + proof[i][:-1])

            if not node_contains(proof[i-1], computed_hash):
                dprint("[ERR TX] "+str(inner_prefix, 'utf-8')+" inner node at depth " + str(i) + "/" + str(len(proof)-1) + " computed hash " + to_hex(computed_hash) + " wasn't found in the node above")
                dprint("[ERR TX] node at "+str(i-1)+": " + to_hex(proof[i-1]))
                return False

        return True

    def process_as_node(self, acc, ledgerSeq, ledgerHash, nodedata, proof):

        #dprint("process_as_node: " + acc + " lgr=" + str(ledgerSeq) + ", " + str(ledgerSeq) + ", " + to_hex(ledgerHash))

        # first make sure we're not waiting on other ledgers 
        if not self.check_ledger_chain(ledgerSeq, ledgerHash):
            #dprint("process_as_node is waiting on ledgers")
            if not ledgerSeq in self.ac_waiting_on_ledgers:
                self.ac_waiting_on_ledgers[ledgerSeq] = {}
            self.ac_waiting_on_ledgers[ledgerSeq][acc] = { "proof": proof, "nodedata": nodedata }
            return False
        


        # the next thing we need to check is top to bottom hashes, i.e. the node proof
        if not self.verify_node_proof(proof, b'MIN\x00', b'MLN\x00'):
            dprint("[ERR AS] process_as_node failed proof check")
            return False

        #dprint("process_as_node verified proof")
                
        # nodes are correct to the tx_root. since the ledger has also been checked before this function is called 
        # we are now in a state where this transaction is verified to be on-ledger as it appears here, so we can record it

        # clean up our entries

        if ledgerSeq in self.ac_waiting_on_ledgers:
            if acc in self.ac_waiting_on_ledgers[ledgerSeq]:
                del self.ac_waiting_on_ledgers[ledgerSeq][acc]
            if len(self.ac_waiting_on_ledgers[ledgerSeq]) == 0:
                del self.ac_waiting_on_ledgers[ledgerSeq]


        sto = parse_stobject(nodedata[:-33], False, False)

        if not sto:
            dprint("[ERR AS] verified account state for " + acc + " but unable to read sto")
            return False

        #dprint("verified account root: " + acc + " prevtxid=" + to_hex(sto['PreviousTxnID']))
        self.add_wanted_tx(sto['PreviousTxnID'], acc, sto['PreviousTxnLgrSeq'])
        return True    
        

    def add_wanted_tx(self, txid, acc, ledgerSeq):
        if not acc in self.accounts:
            dprint("[ERR TX] Tried to add wanted tx to account we don't have in our accounts list")
            return False

        account = self.accounts[acc]

        if not txid in account['tx_chain'] and not txid in account['wanted_tx']:
            account['wanted_tx'][txid] = {
                "ledger_seq_no_at_discovery": ledgerSeq,
                "max_ledger_seq_no": ledgerSeq,
                "aggression": 4,
                "dont_drop": True
            }

        if not ledgerSeq in self.ledger_seq:
            self.wanted_ledgers[ledgerSeq] = False

        return True


    def process_tx_node(self, txid, acc, ledgerSeq, ledgerHash, nodedata, proof):

        #dprint("process_tx_node")

        # first make sure we're not waiting on other ledgers 
        if not self.check_ledger_chain(ledgerSeq, ledgerHash):
            return False
        
        # the next thing we need to check is top to bottom hashes, i.e. the node proof
        if not self.verify_node_proof(proof, b'MIN\x00', b'SND\x00'):
            return False
                
        # nodes are correct to the tx_root. since the ledger has also been checked before this function is called 
        # we are now in a state where this transaction is verified to be on-ledger as it appears here, so we can record it

        # clean up our entries

        if ledgerSeq in self.tx_waiting_on_ledgers:
            if txid in self.tx_waiting_on_ledgers[ledgerSeq]:
                del self.tx_waiting_on_ledgers[ledgerSeq][txid]
            if len(self.tx_waiting_on_ledgers[ledgerSeq]) == 0:
                del self.tx_waiting_on_ledgers[ledgerSeq]

        if acc in self.accounts and 'wanted_tx' in self.accounts[acc] and txid in self.accounts[acc]['wanted_tx']:
            del self.accounts[acc]['wanted_tx'][txid]

        

        vl = parse_vlencoded(nodedata[:-33])
        md = parse_stobject(vl[1], False, True)

        if 'AffectedNodes' in md and 'ModifiedNode' in md['AffectedNodes']:
            modified = md['AffectedNodes']['ModifiedNode']
            if type(modified) != list:
                modified = [modified]

            found_node = False
            for n in modified:
                #dprint(node['FinalFields'])
                if not 'PreviousTxnID' in n or not 'PreviousTxnLgrSeq' in n or  not 'FinalFields' in n:
                    continue

                relevant = False
                for x in n['FinalFields']:
                    if n['FinalFields'][x] == acc:
                        relevant = True
                        break

                if not relevant:
                    #dprint(n['FinalFields'])#['Account'] + " != " + to_hex(self.accounts[acc]['raw']))
                    continue

                ptxid = from_hex(n['PreviousTxnID'])
                ptxseq = n['PreviousTxnLgrSeq']

                if self.config['write_to_file']:
                    WRITE_LOCK.acquire()
                    f = open(acc + "/tx/" + to_hex(txid), "w+")
                    f.write( str(md))
                    f.close()
                    WRITE_LOCK.release()

                if self.config['write_to_stdout']:
                    print(str(md))
    
                found_node = True
                lastseenindex = (ledgerSeq << 32) + md['TransactionIndex']
                
                account = self.accounts[acc]

                account['tx_ledger_seq'][ptxid] = ptxseq
                account['tx_chain'][txid] = ptxid
               
                if account['tx_first_fsi'] < lastseenindex:
                    account['tx_first'] = txid                                            
                    account['tx_first_fsi'] = lastseenindex
    
                if lastseenindex > account['tx_last_lsi']:
                    account['tx_last'] =  txid
                    account['tx_last_lsi'] = lastseenindex

                self.add_wanted_tx(ptxid, acc, ptxseq)

            if not found_node:
                dprint("[ERR TX] skipping tx with missing PreviousTxnID/PreviousTxnLgrSeq " + to_hex(txid))
                return False

        return True


    def request_tx(self, ledger_seq_no, txid):
        return self.request_tx_batch([(ledger_seq_no, ledger_seq_no + 5, txid)])

    def request_tx_batch(self, tuples):
        
        seq_tx_map = {}

        for t in tuples:
            for n in range(t[0], t[1]+1):
                if not n in seq_tx_map:
                    seq_tx_map[n] = []
                seq_tx_map[n].append((t[2], t[3]))       

        for ledger_seq_no in seq_tx_map:
            if ledger_seq_no > self.last_ledger_seq_seen:
                continue
            
            lentosend = len(seq_tx_map[ledger_seq_no])

            packet_size = 20
            packets = lentosend//packet_size + 1

            for p in range(0, packets):
                appended = 0

                gl = ripple_pb2.TMGetLedger()
                gl.ledgerSeq = ledger_seq_no
                gl.itype = ripple_pb2.TMLedgerInfoType.liTX_NODE
                
                count = 0
                for txid, depth in seq_tx_map[ledger_seq_no]:

                    if not count >= p*packet_size:
                        count += 1
                        continue

                    if count >= (p+1) * packet_size:
                        break

                    count += 1

                    if type(txid) == bytes:
                        txid = to_hex(txid)

                    #dprint("requesting " + txid + " from ledger " + str(ledger_seq_no))
                    for l in range(1, depth, 1):
                        v = hex(l)[2:]
                        key = txid[0:l] + ('0' * (66 - l - len(v))) + v
                        gl.nodeIDs.append(from_hex(key))
                        appended += 1

                if appended > 0:
                    #dprint("sending tx req batch p=" + str(p) + " count=" + str(count) + " contains=" + str(appended))
                    gl.queryDepth = 0
                    msg = encode_peer_message('mtGetLedger', gl)
                    con = self.send_rand_peer(msg)
                    if con and self.connections[con]:
                        self.connections[con]['requests'] += 1

                    #send to a second random peer to increase chance of response
                    if len(self.connections) > 1:
                        con = self.send_rand_peer(msg, [con])
                        if con and self.connections[con]:
                            self.connections[con]['requests'] += 1

    def send(self, connection, x):
        try:
            connection.send(x)
            return connection
        except:
            if connection in self.connections:
                del self.connections[connection]  
            dprint("[ERR CX] Send to connection fd=" + str(connection.fileno()) + " failed, removing connection")
            return False        

    def send_rand_peer(self, x, exclude = []):
        sent = False
        while len(self.connections) > len(exclude) and not sent:
            peer = [*self.connections][int(to_hex(os.urandom(4)), 16) % len(self.connections)]
            if peer in exclude:
                continue
            sent = self.send(peer, x)
        return sent


    def request_wanted_tx(self):
        tx_set = []
        tx_drop = []
        for acc in self.accounts:
            for txid in self.accounts[acc]['wanted_tx']:
                if self.accounts[acc]['wanted_tx'][txid]['ledger_seq_no_at_discovery'] <= 0:
                    self.accounts[acc]['wanted_tx'][txid]['ledger_seq_no_at_discovery'] = ledger_seq - 1

                maxseq = self.accounts[acc]['wanted_tx'][txid]['max_ledger_seq_no']
                minseq = self.accounts[acc]['wanted_tx'][txid]['ledger_seq_no_at_discovery']
                if self.accounts[acc]['wanted_tx'][txid]['aggression'] == 3:
                    minseq += 1
                    maxseq = minseq + 1 
                #if maxseq < last_ledger_seq_seen and maxseq + 5 > last_ledger_seq_seen :
                if maxseq + 20 < self.last_ledger_seq_seen and not 'dont_drop' in self.accounts[acc]['wanted_tx'][txid]:
                    tx_drop.append(txid)       
                elif minseq <= self.last_ledger_seq_seen :
                    tx_set.append( (minseq, maxseq, txid, 12 ) ) #accounts[acc]['wanted_tx'][txid]['aggression']) )
                    
                    if self.last_ledger_seq_seen - self.accounts[acc]['wanted_tx'][txid]['ledger_seq_no_at_discovery'] > 2:
                        self.accounts[acc]['wanted_tx'][txid]['aggression'] += 1
                        if self.accounts[acc]['wanted_tx'][txid]['aggression'] > 8:
                            self.accounts[acc]['wanted_tx'][txid]['aggression'] = 8

                    #if 'dont_drop' in  accounts[acc]['wanted_tx'][txid]:
                    #    del  accounts[acc]['wanted_tx'][txid]['dont_drop']

        for txid in tx_drop:
            for acc in self.accounts:
                dprint("[ERR TX] Dropped transaction " + to_hex(txid) + "... couldn't locate it", True) #ledger_added: " + str(self.accounts[acc]['wanted_tx'][txid]['ledger_seq_no_at_discovery']) + " max: " + str(self.accounts[acc]['wanted_tx'][txid]['max_ledger_seq_no']))
                self.accounts[acc]['dropped_tx'].append(txid)
                del self.accounts[acc]['wanted_tx'][txid]

        self.request_tx_batch(tx_set)

    def make_random_connection(self):
        server = [*self.peers][int(to_hex(os.urandom(4)), 16) % len(self.peers)]   
        try:
            connection = self.connect(server)
            if connection:
                self.connections[connection] = {
                    'requests': 0,
                    'responses': 0,
                    'finished_connecting': False
                }
                return True    
            else:
                pass
                #dprint("connection failed")
        except Exception as e:
            #dprint("EXCEPT: " + str(e))
            pass
        return False



    def request_loop(self):
     
        partial = {}

        validations = {}

        def before_continue():
            if len(self.connections) < config['connection_limit']:
                self.make_random_connection()
            elif len(self.connections) == config['connection_limit']:
                prune = []
                for con in self.connections:
                    if not con:
                        prune.append(con)
                        continue
                    if self.connections[con]['requests'] > 50:
                        health = self.connections[con]['responses'] / self.connections[con]['requests']
                        if health < 0.2:
                            #dprint("fd " + str(con.fileno()) + " health = " + str(self.connections[con]['responses'] / self.connections[con]['requests']) + " req: " + str(self.connections[con]['requests']) + " resp: " + str(self.connections[con]['responses'])  )
                            del self.connections[con]
                            break
                #catch anything that shouldn't be in there
                for x in prune:
                    del self.connections[x]
        
        before_continue()
        while True:

            if len(self.connections) == 0:
                before_continue()
                continue 
            
            writable = []
            exceptional = []
            readable = []

            try:
                readable, writable, exceptional = select.select([*self.connections], writable, [*self.connections])
            except Exception as e:
                to_dump = []
                for con in self.connections:
                    if con.fileno() < 0:
                        to_dump.append(con)
                for con in to_dump:
                    dprint("[ERR CX] Dumping connection due to negative fd")
                    del self.connections[con]
                before_continue()
                continue

            for connection in exceptional:
                #dprint("!!!!!!!Exceptional status on fd = " + str(self.connection.fileno()))
                if connection in self.connections:
                    del self.connections[connection]
                before_continue()
                continue

            readable_ordered = []
            for connection in readable:
                if self.connections[connection]['finished_connecting']:
                    readable_ordered.append(connection)

            for connection in readable:
                if not self.connections[connection]['finished_connecting']:
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

                if not self.connections[connection]['finished_connecting']:
                    if self.finish_connecting(connection, raw_packet):
                        self.connections[connection]['finished_connecting'] = True
                    else:
                        try:
                            del self.connections[connection]
                        except:
                            pass
                    continue

                if fd in partial:
                    partial[fd]['message_upto'] += len(raw_packet)
                    partial[fd]['message'].append(raw_packet)
                    #dprint("waiting for more data to complete message... " + str(partial[fd]['message_upto']) + "/" + str(partial[fd]['message_size']))
                    if partial[fd]['message_upto'] < partial[fd]['message_size']:
                        continue
            
                    #execution to here means we've finished parsing our mega packet
                    raw_packet = b''.join(partial[fd]['message'])
                    del partial[fd]
                
                #parse the 6 byte header which is in network byte order
                message_size = int.from_bytes(raw_packet[0:4], byteorder='big')
                message_type = int.from_bytes(raw_packet[4:6], byteorder='big')
                message_type_str = peer_message_type_to_string(message_type)

                if len(raw_packet) < message_size:
                    partial[fd] = {
                        "message_size": message_size,
                        "message_upto": len(raw_packet) - 6,
                        "message": [raw_packet]
                    }
                    #dprint("waiting for more data to complete messag on fd="+str(fd)+"e... " + str(partial[fd]['message_upto']) + "/" + str(partial[fd]['message_size']))
                    continue

                #parse the message itself
                message = parse_peer_message(message_type, raw_packet[6:message_size+6])

                if not message:
                    dprint("[ERR CX] Received unreadable message")
                    continue

                #check for pings and respond with a pong
                if message_type == 3: #(mtPING)
                    message.type = message.ptPONG
                    try: 
                        connection.send(encode_peer_message('mtPing', message)) 
                    except:
                        if connection in connections:
                            del connections[connection]
                            continue

                # these are the state xfer messages we're interested in
                if message_type == 32: #(mtLEDGER_DATA)
                    if connection and self.connections[connection]:
                        self.connections[connection]['responses'] += 1

                    if message.type == ripple_pb2.TMLedgerInfoType.liTX_NODE:
                        for x in message.nodes:
                            if not x.nodedata[-1] == 4:
                                continue
                            
                            h = to_hex(x.nodedata)
                            txid = from_hex(h[-66:-2])
                            
                            for acc in self.accounts:
                                if txid in self.accounts[acc]['wanted_tx']:

                                    dprint("[GOT TX] " + to_hex(txid))# + " FOUND IN LEDGER " + str(message.ledgerSeq) + " ORIGINAL ESTIMATE:" + str(self.accounts[acc]['wanted_tx'][txid]['ledger_seq_no_at_discovery'] ))

                                    #rather inefficient way to gather the nodes we need to prove the metadata is true and correct
                                    proof_nodes = []
                                    requested_node = to_hex(txid)
                                    for l in range(1, len(requested_node)):
                                        v = hex(l)[2:]
                                        key = from_hex(requested_node[0:l] + ('0' * (66 - l - len(v))) + v)
                                        for y in message.nodes:
                                            if y.nodeid == key:
                                                proof_nodes.append(decompress_node(y.nodedata))
                                                break

                                    #nb: the tx root needs to be front-pushed onto proof_nodes before computation

                                    if not message.ledgerHash in self.ledger_chain:
                                        #dprint("transaction was not part of a ledger we know of adding wanted ledger " + to_hex(message.ledgerHash))
                                        self.wanted_ledgers[message.ledgerSeq] = message.ledgerHash
                                        if not message.ledgerSeq in self.tx_waiting_on_ledgers:
                                            self.tx_waiting_on_ledgers[message.ledgerSeq] = { txid: { "proof": proof_nodes, "nodedata": x.nodedata, 'acc': acc } }
                                        else:
                                            self.tx_waiting_on_ledgers[message.ledgerSeq][txid] = { "proof": proof_nodes, "nodedata": x.nodedata, 'acc': acc }
                                        before_continue()
                                        continue
                                    else:
                                        proof_nodes.insert(0, self.ledger_chain[message.ledgerHash]['tx_root'])

                                    self.process_tx_node(txid, acc, message.ledgerSeq, message.ledgerHash, x.nodedata, proof_nodes)

                                missing = 0
                                for tx in account['tx_chain']:
                                    if not account['tx_chain'][tx] in account['tx_chain']:
                                        missing += 1
                                        if not tx in account['wanted_tx']:
                                            if tx in account['tx_ledger_seq']:
                                                account['wanted_tx'][tx] = {
                                                    "ledger_seq_no_at_discovery": account['tx_ledger_seq'][tx],
                                                    "max_ledger_seq_no": account['tx_ledger_seq'][tx],
                                                    "aggression": 4,
                                                    "dont_drop": True
                                                }
                                                #dprint("Adding missing TXID to wanted:" + acc + " txid " + \
                                                #to_hex(tx) + " ldgseq=" + str(account['tx_ledger_seq'][tx]))
                                            #else:
                                            #    dprint("MISSING txid " + acc + " txid " + to_hex(tx) + " but no idea which ledger to look in")

                                if missing > 2:
                                    msg = "[INF TX] Missing transactions >=" + str(missing) + " out of " + str(len(account['tx_chain']))
                                    if msg != self.last_missing_msg:
                                        dprint(msg)
                                        self.last_missing_msg = msg

                    elif message.type == ripple_pb2.TMLedgerInfoType.liBASE:
                            
                        # first check if we even asked for this ledger
                        if not message.ledgerSeq in self.wanted_ledgers and not message.ledgerHash in self.ledgers_waiting_on_ledgers:
                            dprint("[ERR CX] Peer attempted to send ledger info we didn't ask for seq=" + str(message.ledgerSeq) + ", hash=" + to_hex(message.ledgerHash))
                            before_continue()
                            continue
                
                        # next check if its a valid base message
                        if len(message.nodes) <= 0:
                            dprint("[ERR CX] Invalid liBASE with no nodes")
                            before_continue()
                            continue

                        # now check if the top level hash is correct
                        computed_ledger_hash =  SHA512H(b'LWR\x00' +  message.nodes[0].nodedata)
                        if message.ledgerHash != SHA512H(b'LWR\x00' +  message.nodes[0].nodedata):
                            dprint("[ERR CX] Invalid ilBASE node, stated hash was: " + to_hex(message.ledgerHash) + " but comuted hash was: " + to_hex(computed_ledger_hash))
                            before_continue()
                            continue

                        # it's unlikely but possible the root nodes are compressed, so deal with that first
                        message.nodes[1].nodedata = decompress_node(message.nodes[1].nodedata)
                        message.nodes[2].nodedata = decompress_node(message.nodes[2].nodedata)

                        # parse the master
                        lr = parse_ledger_root(message.nodes[0].nodedata)

                        # now check if the next level hashes are correct
                        cal_ac_root_hash = SHA512H(b'MIN\x00' + message.nodes[1].nodedata[:-1])
                        cal_tx_root_hash = SHA512H(b"MIN\x00" + message.nodes[2].nodedata[:-1])
                        rep_ac_root_hash = lr['accountHash']
                        rep_tx_root_hash = lr['txHash']
                        
                        if cal_ac_root_hash != rep_ac_root_hash:
                            dprint("[ERR CX] Invalid ilBASE node: calculated and reported acc root hash don't match: c=" + to_hex(cal_ac_root_hash) + " r=" + to_hex(rep_ac_root_hash))
                            before_continue()
                            continue

                        if cal_tx_root_hash != rep_tx_root_hash:
                            dprint("[ERR CX] Invalid ilBASE node: calculated and reported tx root hash don't match: c=" + to_hex(cal_tx_root_hash) + " r=" + to_hex(rep_tx_root_hash))
                            before_continue()
                            continue

                        # execution to here means the base ledger is internally consistent/correct

                        self.ledger_chain[message.ledgerHash] = {
                            "ledger_seq_no": message.ledgerSeq,
                            "prev_ledger_hash": message.nodes[0].nodedata[12:44]
                        }
                        self.ledger_seq[message.ledgerSeq] = message.ledgerHash
                        # record these hashes and the root node verification for use later
                        self.ledger_chain[message.ledgerHash]['root'] = message.nodes[0]
                        self.ledger_chain[message.ledgerHash]['ac_root'] = cal_ac_root_hash
                        self.ledger_chain[message.ledgerHash]['tx_root'] = cal_tx_root_hash
                    
                        # update head and tail records when appropriate 
                        if self.last_ledger_seq_verified == False or message.ledgerSeq > self.last_ledger_seq_verified:
                            self.last_ledger_seq_verified = message.ledgerSeq
                            self.last_ledger_hash_verified = message.ledgerHash

                        if self.first_ledger_seq_verified == False or message.ledgerSeq < self.first_ledger_seq_verified:
                            self.first_ledger_seq_verified = message.ledgerSeq
                            self.first_ledger_hash_verified = message.ledgerHash

                        #dprint("REMOVED LEDGER: seq=" + str(message.ledgerSeq) + " hash=" + to_hex(message.ledgerHash))

                        # remove the ledger from our wanted list
                        if message.ledgerSeq in self.wanted_ledgers:
                            del self.wanted_ledgers[message.ledgerSeq]
                       


                        # find and process any received tx that were waiting on this ledger base
                        def reprocess_waiting(ledgerSeq, ledgerHash):
                            if ledgerSeq in self.tx_waiting_on_ledgers:
                                to_process = []
                                for txid in self.tx_waiting_on_ledgers[ledgerSeq]:
                                    dprint("[GOT TX] " + to_hex(txid))
                                    tx = self.tx_waiting_on_ledgers[ledgerSeq][txid]
                                    proof = [self.ledger_chain[ledgerHash]['tx_root'], * self.tx_waiting_on_ledgers[ledgerSeq][txid]['proof']]
                                    to_process.append( (txid, tx['acc'], ledgerSeq, ledgerHash, tx['nodedata'], proof) )

                                for txid, acc, ls, lh, nd, proof in to_process:
                                    self.process_tx_node(txid, acc, ls, lh, nd, proof)
                            
                            if ledgerSeq in self.ac_waiting_on_ledgers:
                                to_process = []
                                for acc in self.ac_waiting_on_ledgers[ledgerSeq]:
                                    dprint("[GOT LG] " + to_hex(ledgerHash))# + " now PROCESSING acc_root: " + acc + " !!")
                                    ac = self.ac_waiting_on_ledgers[ledgerSeq][acc]
                                    proof = [self.ledger_chain[ledgerHash]['ac_root'], * self.ac_waiting_on_ledgers[ledgerSeq][acc]['proof']]
                                    to_process.append( (acc, ledgerSeq, ledgerHash, ac['nodedata'], proof) )

                                for acc, ls, lh, nd, proof in to_process:
                                    self.process_as_node(acc, ls, lh, nd, proof)
                            
                            
                        
                        if message.ledgerHash in self.ledgers_waiting_on_ledgers:
                            waiting_set = self.ledgers_waiting_on_ledgers[message.ledgerHash]
                            # reprocess all waiting tx in all ledgers in waiting set
                            dprint("[GOT LG] " + to_hex(message.ledgerHash))
                            for lh in waiting_set:
                                if lh in self.ledger_seq:
                                    reprocess_waiting(self.ledger_seq[lh], lh)
                            del self.ledgers_waiting_on_ledgers[message.ledgerHash]

                        reprocess_waiting(message.ledgerSeq, message.ledgerHash)


                    elif message.type == ripple_pb2.TMLedgerInfoType.liAS_NODE:
                        #dprint("liAS_NODE")

                        # the AS_NODE might have lots of entries for lots of account's we're interested in,
                        # so first do a preliminary loop to find out which accounts this AS_NODE contains
                                    
                        proof_needed = {} # asroot_key -> acc
                        proof_nodes = {} # acc -> [ proof nodes ]
                        nodedata = {} # acc -> leaf nodedata

                        for x in message.nodes:
                            nodetype = x.nodedata[-1]
                            if not nodetype == 1: # we're looking only at leaf nodes initially
                                continue
                            node_asroot_key = x.nodedata[-33:-1]
                            for acc in self.accounts:
                                if self.accounts[acc]['asroot_key_raw'] == node_asroot_key:
                                    proof_needed[self.accounts[acc]['asroot_key']] = acc
                                    proof_nodes[acc] = []
                                    nodedata[acc] = x.nodedata

                        # if this packet contains nothing of interest move on
                        if len(proof_needed) == 0:
                            dprint("[ERR CX] Account state received but contained no accounts we are watching")
                            before_continue()
                            continue
                        
                        # on second pass we will build the node proofs for each account whose proof appears in this packet
                        for x in message.nodes:
                            for requested_node in proof_needed:
                                acc = proof_needed[requested_node]
                                for l in range(1, len(requested_node)):
                                    v = hex(l)[2:]
                                    key = from_hex(requested_node[0:l] + ('0' * (66 - l - len(v))) + v)
                                    if x.nodeid == key:
                                        x.nodedata = decompress_node(x.nodedata)
                                        proof_nodes[acc].append(x.nodedata)
                                        break
                                
                         # execution to here means the proof has been collected for each account, but we need to ensure
                         # the ledger base was retreived

                        if not message.ledgerHash in self.ledger_chain:
                            dprint("[INF AS] Account state was not part of a ledger we know of, adding wanted ledger " + to_hex(message.ledgerHash))
                            self.wanted_ledgers[message.ledgerSeq] = message.ledgerHash
                            if not message.ledgerSeq in self.ac_waiting_on_ledgers:
                                self.ac_waiting_on_ledgers[message.ledgerSeq] = {}
                            for acc in proof_nodes:
                                self.ac_waiting_on_ledgers[message.ledgerSeq][acc] = { "proof": proof_nodes[acc], "nodedata": nodedata[acc] }
                            before_continue()
                            continue
                        else:
                            for acc in proof_nodes:
                                proof_nodes[acc].insert(0, self.ledger_chain[message.ledgerHash]['ac_root'])

                        for acc in proof_nodes:
                            self.process_as_node(acc, message.ledgerSeq, message.ledgerHash, nodedata[acc], proof_nodes[acc])
       

                if message_type == 42: #GetObjectByHash
                    pass
                    #dprint('get object by hash: -------')
                    #dprint(message)
                    #dprint('-----------')

                if message_type == 30: #Transaction
                    #wait for at least one validation before we start wanting tx
                    if self.last_ledger_seq_seen == -1:
                        continue

                    
                    #dprint('mtTransaction: ' + to_hex(SHA512HP(b'TXN\x00', message.rawTransaction))
                    

                    # filter cheaply before parsing 
                    found = False
                    for acc in self.accounts:
                        if message.rawTransaction.find(self.accounts[acc]['raw']):
                            found = True
                            break

                    if not found:
                        continue

                    tx = parse_stobject(message.rawTransaction, False, False)
                     
                    if tx:
                        for acc in self.accounts:
                            if self.accounts[acc]['raw'] == tx['Account'] or 'Destination' in tx and self.accounts[acc]['raw'] == tx['Destination']:

                                account = self.accounts[acc]

                                txid = SHA512HP(b'TXN\x00', message.rawTransaction)
                                if txid in self.accounts[acc]['wanted_tx']:
                                    break

                                seq = tx['Sequence']
                                #if int(to_hex(txid[0:2]), 16) % 20 == 0:
                                #    dprint("dropping tx " + to_hex(txid) + " for testing, seq=" + str(seq))
                                #    continue 

                                if 'Destination' in tx and account['raw'] == tx['Destination']:
                                    seq = -1

                                account['wanted_tx'][txid] = {
                                    "ledger_seq_no_at_discovery": self.last_ledger_seq_seen,
                                    "max_ledger_seq_no": tx['LastLedgerSequence'],
                                    "aggression": 3
                                }
                                dprint('[ASK TX] ' + to_hex(txid))
# + "[W"+str(len(account['wanted_tx']))+" D"+str(len(account['dropped_tx']))+"]" + ", " + str(tx['Sequence']) + " {" + str(self.last_ledger_seq_seen) + "}  " + to_hex(txid))
                                break
            
                if message_type == 15: #(mtEndpoints)
                    #dprint('mtEndpoints')
                    added = False
                    for endpoint in message.endpoints_v2:
                        ip = endpoint.endpoint.replace('[::', '').replace('ffff:', '').replace(']', '')
                        if re.match(r'^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}$', ip) != None:
                            if not ip in self.peers:
                                self.peers.add(ip)
                                added = True

                    if added:
                        if self.config['allow_write_to_peer_file']:
                            self.write_peer_file()
    
                
                if message_type == 41: #(mtVALIDATION)
                    #todo check if validations are from our selected UNL
                    sto = parse_stobject(message.validation, False, False)

                    ledger_hash = sto['LedgerHash']
                    ledger_seq = sto['LedgerSequence'] # int(message.validation.hex()[12:20], 16) #todo change this to pull from sto
                    
                    signing_key = sto['SigningPubKey']

                    # check if the signing key is in our UNL
                    if not signing_key in config['UNL']:
                        continue

                    # these are secp256k1 signatures
                    # todo: convert other parts of this program that use secp256k1 to fastecdsa
                    sig = sto['Signature']
                    vk = fastecdsa.encoding.sec1.SEC1Encoder.decode_public_key(signing_key, curve=fastecdsa.curve.secp256k1)
                    h = to_hex(SHA512H(b'VAL\x00' + message.validation[:117])) # 117 is the offset after which there are signatures and someitmes ammendment voting
                    sig = fastecdsa.encoding.der.DEREncoder.decode_signature(sig)
                    if not fastecdsa.ecdsa.verify(sig,  h, vk, curve=fastecdsa.curve.secp256k1, hashfunc=CPASS):
                        dprint("[ERR VA] UNL validation continaing an invalid signature from " + to_hex(signing_key), True)
                        continue
            
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
                    if signing_key in config['UNL'] and not signing_key in validations[ledger_hash]:
                        validations[ledger_hash][signing_key] = ledger_seq
                   

                    if len(validations[ledger_hash]) < len(self.config['UNL']) * 0.8:
                        continue
                    
                    if self.last_ledger_seq_seen >= ledger_seq:
                        continue


                    self.last_ledger_seq_seen = ledger_seq
                    self.last_ledger_hash_seen = ledger_hash
                
                    dprint("[VAL LG] Validated ledger " +  str(ledger_seq) + " received", True)

                    self.request_wanted_tx()

                    dprint("[ASK LG] " + to_hex(ledger_hash)) 
                    self.wanted_ledgers[ledger_seq] = ledger_hash

                    already_requested = set()
                    for ls in self.wanted_ledgers:
                        gl = ripple_pb2.TMGetLedger()
                        if ls in self.wanted_ledgers and self.wanted_ledgers[ls] != False:
                            gl.ledgerHash = self.wanted_ledgers[ls]
                            already_requested.add(self.wanted_ledgers[ls])
                        gl.ledgerSeq = ls 
                        gl.queryDepth = 1
                        gl.itype = ripple_pb2.TMLedgerInfoType.liBASE
                        self.send_rand_peer(encode_peer_message('mtGetLedger', gl))
                        dprint("[ASK LG] " + str(ls))
                    
                    for lh in self.ledgers_waiting_on_ledgers:
                        if not lh in already_requested:
                            gl = ripple_pb2.TMGetLedger()
                            gl.ledgerHash = lh
                            gl.queryDepth = 1
                            gl.itype = ripple_pb2.TMLedgerInfoType.liBASE
                            self.send_rand_peer(encode_peer_message('mtGetLedger', gl))
                            dprint("[ASK LG] " + to_hex(lh))

                    # request AS_ROOT every 5 ledgers
                    if not ledger_seq % 5 == 0:
                        before_continue()
                        continue

                    for acc in self.accounts:

                        account = self.accounts[acc]
                        requested_node = account['asroot_key']

                        dprint('[ASK AS] ' + requested_node)
                        # now request the account state info
                        gl = ripple_pb2.TMGetLedger()
                        gl.ledgerSeq = self.last_ledger_seq_verified
                        gl.itype = ripple_pb2.TMLedgerInfoType.liAS_NODE
                       
                        for l in range(1, len(requested_node)):
                            v = hex(l)[2:]
                            key = requested_node[0:l] + ('0' * (66 - l - len(v))) + v
                            gl.nodeIDs.append(from_hex(key))

                        gl.queryDepth = 0
                        self.send_rand_peer(encode_peer_message('mtGetLedger', gl))
                    
            before_continue()
            continue    


node = xrpl_ultralite(config)
node.request_loop()

