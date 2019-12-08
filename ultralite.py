# XRPL UltraLite
#   Author: Richard Holland

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
from util import *

#------------- start config


config = {
    "bootstrap_server": "s1.ripple.com:51235", #this will be connected to if no peers are currently available from the peer file
    "full_history_peers": ["s2.ripple.com"], # we will use these to backfill our transaction history
    "UNL": [], #we'll populate from the below if specified
    "validator_site": "https://vl.ripple.com",
    "peer_file": "peers.txt",
    "connection_limit": 2
}

#------------- end config


# these are global state variables

class xrpl_ultralite:

    ledger_chain = {} # ledger_hash -> { prev_ledger_hash: , seq_no: , account_root: , tx_root: , root: }
    ledger_seq = {} # ledger_seqno -> ledger_hash

    wanted_ledgers = {} # wanted ledger seq no -> ledger hash or False
    tx_waiting_on_ledgers = {} # wanted ledger seq -> txid -> { "proof": proof_nodes, "nodedata": x.nodedata, 'acc': acc } 
    ac_waiting_on_ledgers = {} # wanted ledger seq -> acc -> { "proof": , "nodedata": }

    ledgers_waiting_on_ledgers = {} # wanted ledger hash -> legder has to reprocess for tx once wanted ledger is received

    last_missing_msg = "" # used to supress missing repeating message output

    accounts = {}
    peers = set()
    connections = {}

    last_ledger_seq_no = -1
    last_ledger_hash = False


    node_sk = ""
    node_vk = ""
    node_b58pk = ""
    config = None

    
    def __init__(self, config):
        self.config = config

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

        if os.path.exists(self.config['peer_file']):
            f = open(self.config['peer_file'], "r+")
            if f:
                content = f.readlines()
                f.close()
                for ip in content:
                    self.peers.add(ip)
           
        self.peers.add(config['bootstrap_server'])
        
        # build UNL from the validator site specified, if any
        if type(self.config['validator_site']) == str and len(self.config['validator_site']) > 0:
            context = ssl._create_unverified_context()
            vl = urllib.request.urlopen(config['validator_site'],  context=context).read().decode('utf-8')
            vl = json.loads(vl)
            if vl['public_key'].upper() != 'ED2677ABFFD1B33AC6FBC3062B71F1E8397C1505E1C42C64D11AD1B28FF73F4734':
                print("attempted to fetch validator list from " + self.config['validator_site'] + " but found unknown list signing key!")
                exit(1)
            #todo: check validator list signature here

            payload = json.loads(base64.b64decode(vl['blob']))
            st = base64.b64decode(payload['validators'][0]['manifest'])
            for v in payload['validators']:
                #todo: check signatures of each validator here
                sto = parse_stobject(base64.b64decode(v['manifest']))
                self.config['UNL'].append(sto['SigningPubKey']) 

            print("Loaded a UNL from validator site " + self.config['validator_site'] + " consisting of " + str(len(self.config['UNL'])) + " validators")
        
        argv = sys.argv[1:]
        
        # process commandline
        if len(argv) == 0:
            print("usage: " + sys.argv[0] + " rSomeAccountToWatch rSomeOtherAccountToWatch ...")
            quit()

        binprefix = b'\x00a'
        if type(binprefix) == str: #leave this here in case we change the way binprefix is provided later
            binprefix = from_hex(binprefix)

        for raccount in argv:
            acc = raccount
            
            if raccount != False and type(raccount) == str:
                if raccount[0] == 'r':
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



    def connect(self, server):
        server = server.replace("\r", "").replace("\n", "")       
        print("Attempting to connect to " + server + ", connections=" + str(len(self.connections)) )
        
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




    def check_ledger_chain(self, ledgerSeq, ledgerHash):
        # before we process, we need to ensure there is a complete chain from lcl back to the ledger
        # this tx appeared in

        if not self.last_ledger_hash or not self.last_ledger_hash in self.ledger_chain:
            if self.last_ledger_hash in self.ledgers_waiting_on_ledgers:
                self.ledgers_waiting_on_ledgers[self.last_ledger_hash].add(ledgerHash)
            else:
                self.ledgers_waiting_on_ledgers[self.last_ledger_hash] = set(ledgerHash)
            return False

        p = self.ledger_chain[self.last_ledger_hash]['prev_ledger_hash']
        while p in self.ledger_chain:
            print(to_hex(p))
            if p == ledgerHash:
                break
            p = self.ledger_chain[p]['prev_ledger_hash']

        if p != ledgerHash:
            if p in self.ledgers_waiting_on_ledgers:
                self.ledgers_waiting_on_ledgers[p].add(ledgerHash)
            else:
                self.ledgers_waiting_on_ledgers[p] = set(ledgerHash)
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
                print("!$!$ "+str(inner_prefix, 'utf-8')+" inner node at depth " + str(i) + "/" + str(len(proof)-1) + " computed hash " + to_hex(computed_hash) + " wasn't found in the node above")
                print("TXNODE at "+str(i-1)+": " + to_hex(proof[i-1]))
                return False

        return True

    def process_as_node(self, acc, ledgerSeq, ledgerHash, nodedata, proof):

        print("process_as_node: " + acc + " lgr=" + str(ledgerSeq) + ", " + str(ledgerSeq) + ", " + to_hex(ledgerHash))

        # first make sure we're not waiting on other ledgers 
        if not self.check_ledger_chain(ledgerSeq, ledgerHash):
            print("process_as_node is waiting on ledgers")
            if not ledgerSeq in self.ac_waiting_on_ledgers:
                self.ac_waiting_on_ledgers[ledgerSeq] = {}
            self.ac_waiting_on_ledgers[ledgerSeq][acc] = { "proof": proof, "nodedata": nodedata }
            return False
        


        # the next thing we need to check is top to bottom hashes, i.e. the node proof
        if not self.verify_node_proof(proof, b'MIN\x00', b'MLN\x00'):
            print("process_as_node failed proof check")
            return False

        print("process_as_node verified proof")
                
        # nodes are correct to the tx_root. since the ledger has also been checked before this function is called 
        # we are now in a state where this transaction is verified to be on-ledger as it appears here, so we can record it

        # clean up our entries

        if ledgerSeq in self.ac_waiting_on_ledgers:
            if acc in self.ac_waiting_on_ledgers[ledgerSeq]:
                del self.ac_waiting_on_ledgers[ledgerSeq][acc]
            if len(self.ac_waiting_on_ledgers[ledgerSeq]) == 0:
                del self.ac_waiting_on_ledgers[ledgerSeq]


        sto = parse_stobject(nodedata[:-33], False)

        if not sto:
            print("verified account state for " + acc + " but unable to read sto")
            return False

        print("verified account root: " + acc + " prevtxid=" + to_hex(sto['PreviousTxnID']))
        self.add_wanted_tx(sto['PreviousTxnID'], acc, sto['PreviousTxnLgrSeq'])
        return True    
        

    def add_wanted_tx(self, txid, acc, ledgerSeq):
        if not acc in self.accounts:
            print("Warning: Tried to add wanted tx to account we don't have in our accounts list")
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
        md = parse_stobject(vl[1], False)

        if 'AffectedNodes' in md and 'ModifiedNode' in md['AffectedNodes']:
            modified = md['AffectedNodes']['ModifiedNode']
            if type(modified) != list:
                modified = [modified]

            found_node = False
            for n in modified:
                #print(node['FinalFields'])
                if not 'PreviousTxnID' in n or \
                not 'PreviousTxnLgrSeq' in n or \
                not 'FinalFields' in n or \
                not 'Account' in n['FinalFields'] or \
                not n['FinalFields']['Account'] == self.accounts[acc]['raw']:
                    continue

                f = open(acc + "/tx/" + to_hex(txid), "w+")
                f.write(str(to_hex(n['PreviousTxnID'])) + "\n")
                f.write(str(proof) + "\n")
                f.write( str(md))
                
                f.close()

                found_node = True
                lastseenindex = (ledgerSeq << 32) + md['TransactionIndex']
                
                account = self.accounts[acc]

                account['tx_ledger_seq'][n['PreviousTxnID']] = n['PreviousTxnLgrSeq']
                account['tx_chain'][txid] = n['PreviousTxnID']
               
                if account['tx_first_fsi'] < lastseenindex:
                    account['tx_first'] = txid                                            
                    account['tx_first_fsi'] = lastseenindex
    
                if lastseenindex > account['tx_last_lsi']:
                    account['tx_last'] =  txid
                    account['tx_last_lsi'] = lastseenindex

                self.add_wanted_tx(n['PreviousTxnID'], acc, n['PreviousTxnLgrSeq'])

            if not found_node:
                print("skipping tx with missing PreviousTxnID/PreviousTxnLgrSeq " + to_hex(txid))
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
            if ledger_seq_no > self.last_ledger_seq_no:
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

                    #print("requesting " + txid + " from ledger " + str(ledger_seq_no))
                    for l in range(1, depth, 1):
                        v = hex(l)[2:]
                        key = txid[0:l] + ('0' * (66 - l - len(v))) + v
                        gl.nodeIDs.append(from_hex(key))
                        appended += 1

                if appended > 0:
                    #print("sending tx req batch p=" + str(p) + " count=" + str(count) + " contains=" + str(appended))
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
            print("send to connection fd=" + str(connection.fileno()) + " failed, removing connection")
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
                #if maxseq < last_ledger_seq_no and maxseq + 5 > last_ledger_seq_no :
                if maxseq + 20 < self.last_ledger_seq_no and not 'dont_drop' in self.accounts[acc]['wanted_tx'][txid]:
                    tx_drop.append(txid)       
                elif minseq <= self.last_ledger_seq_no :
                    tx_set.append( (minseq, maxseq, txid, 12 ) ) #accounts[acc]['wanted_tx'][txid]['aggression']) )
                    
                    if self.last_ledger_seq_no - self.accounts[acc]['wanted_tx'][txid]['ledger_seq_no_at_discovery'] > 2:
                        self.accounts[acc]['wanted_tx'][txid]['aggression'] += 1
                        if self.accounts[acc]['wanted_tx'][txid]['aggression'] > 8:
                            self.accounts[acc]['wanted_tx'][txid]['aggression'] = 8

                    #if 'dont_drop' in  accounts[acc]['wanted_tx'][txid]:
                    #    del  accounts[acc]['wanted_tx'][txid]['dont_drop']

        for txid in tx_drop:
            for acc in self.accounts:
                print("DROPPED " + to_hex(txid) + " ledger_added: " + str(self.accounts[acc]['wanted_tx'][txid]['ledger_seq_no_at_discovery']) + " max: " + str(self.accounts[acc]['wanted_tx'][txid]['max_ledger_seq_no']))
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
                print("connection failed")
        except Exception as e:
            print("987")
            print(e)
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
                            print("fd " + str(con.fileno()) + " health = " + str(self.connections[con]['responses'] / self.connections[con]['requests']) + " req: " + str(self.connections[con]['requests']) + " resp: " + str(self.connections[con]['responses'])  )
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
            except:
                to_dump = []
                for con in self.connections:
                    if con.fileno() < 0:
                        to_dump.append(con)
                for con in to_dump:
                    print("DUMPING connection due to negative fd")
                    del self.connections[con]
                before_continue()
                continue

            for connection in exceptional:
                print("!!!!!!!Exceptional status on fd = " + str(self.connection.fileno()))
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
                    #print("waiting for more data to complete message... " + str(partial[fd]['message_upto']) + "/" + str(partial[fd]['message_size']))
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
                    #print("waiting for more data to complete messag on fd="+str(fd)+"e... " + str(partial[fd]['message_upto']) + "/" + str(partial[fd]['message_size']))
                    continue

                #parse the message itself
                message = parse_peer_message(message_type, raw_packet[6:message_size+6])

                if not message:
                    print("WARNING unreadable message")
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

                                    #print("REMOVED :" + to_hex(txid) + " FOUND IN LEDGER " + str(message.ledgerSeq) + " ORIGINAL ESTIMATE:" + str(self.accounts[acc]['wanted_tx'][txid]['ledger_seq_no_at_discovery'] ))

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
                                        #print("transaction was not part of a ledger we know of adding wanted ledger " + to_hex(message.ledgerHash))
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
                                                print("Adding missing TXID to wanted:" + acc + " txid " + \
                                                to_hex(tx) + " ldgseq=" + str(account['tx_ledger_seq'][tx]))
                                            else:
                                                print("MISSING txid " + acc + " txid " + to_hex(tx) + " but no idea which ledger to look in")

                                if (missing > 0):
                                    msg = "missing transactions: >=" + str(missing) + " out of " + str(len(account['tx_chain']))
                                    if msg != self.last_missing_msg:
                                        print(msg)
                                        self.last_missing_msg = msg

                    elif message.type == ripple_pb2.TMLedgerInfoType.liBASE:
                            
                        # first check if we even asked for this ledger
                        if not message.ledgerSeq in self.wanted_ledgers and not message.ledgerHash in self.ledgers_waiting_on_ledgers:
                            print("peer attempted to send ledger info we didn't ask for seq=" + str(message.ledgerSeq) + ", hash=" + to_hex(message.ledgerHash))
                            before_continue()
                            continue
                
                        # next check if its a valid base message
                        if len(message.nodes) <= 0:
                            print("1 invalid liBASE with no nodes")
                            before_continue()
                            continue

                        # now check if the top level hash is correct
                        computed_ledger_hash =  SHA512H(b'LWR\x00' +  message.nodes[0].nodedata)
                        if message.ledgerHash != SHA512H(b'LWR\x00' +  message.nodes[0].nodedata):
                            print("2 invalid ilBASE node, stated hash was: " + to_hex(message.ledgerHash) + " but comuted hash was: " + to_hex(computed_ledger_hash))
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
                            print("3 invalid ilBASE node: calculated and reported acc root hash don't match: c=" + to_hex(cal_ac_root_hash) + " r=" + to_hex(rep_ac_root_hash))
                            before_continue()
                            continue

                        if cal_tx_root_hash != rep_tx_root_hash:
                            print("4 invalid ilBASE node: calculated and reported tx root hash don't match: c=" + to_hex(cal_tx_root_hash) + " r=" + to_hex(rep_tx_root_hash))
                            before_continue()
                            continue

                        # execution to here means the base ledger is internally consistent/correct

                        self.ledger_chain[message.ledgerHash] = {
                            "ledger_seq_no": message.ledgerSeq,
                            "prev_ledger_hash": message.nodes[0].nodedata[12:44]
                        }
                        self.ledger_seq[message.ledgerSeq] = message.ledgerHash
                        #record these hashes and the root node verification for use later
                        self.ledger_chain[message.ledgerHash]['root'] = message.nodes[0]
                        self.ledger_chain[message.ledgerHash]['ac_root'] = cal_ac_root_hash
                        self.ledger_chain[message.ledgerHash]['tx_root'] = cal_tx_root_hash
                    
                        #print("REMOVED LEDGER: seq=" + str(message.ledgerSeq) + " hash=" + to_hex(message.ledgerHash))

                        # remove the ledger from our wanted list
                        if message.ledgerSeq in self.wanted_ledgers:
                            del self.wanted_ledgers[message.ledgerSeq]
                       


                        # find and process any received tx that were waiting on this ledger base
                        def reprocess_waiting(ledgerSeq, ledgerHash):
                            if ledgerSeq in self.tx_waiting_on_ledgers:
                                to_process = []
                                for txid in self.tx_waiting_on_ledgers[ledgerSeq]:
                                    print("RECEIVED " + to_hex(ledgerHash) + " now PROCESSING " + to_hex(txid) + " !!")
                                    tx = self.tx_waiting_on_ledgers[ledgerSeq][txid]
                                    proof = [self.ledger_chain[ledgerHash]['tx_root'], * self.tx_waiting_on_ledgers[ledgerSeq][txid]['proof']]
                                    to_process.append( (txid, tx['acc'], ledgerSeq, ledgerHash, tx['nodedata'], proof) )

                                for txid, acc, ls, lh, nd, proof in to_process:
                                    self.process_tx_node(txid, acc, ls, lh, nd, proof)
                            
                            if ledgerSeq in self.ac_waiting_on_ledgers:
                                to_process = []
                                for acc in self.ac_waiting_on_ledgers[ledgerSeq]:
                                    print("RECEIVED " + to_hex(ledgerHash) + " now PROCESSING acc_root: " + acc + " !!")
                                    ac = self.ac_waiting_on_ledgers[ledgerSeq][acc]
                                    proof = [self.ledger_chain[ledgerHash]['ac_root'], * self.ac_waiting_on_ledgers[ledgerSeq][acc]['proof']]
                                    to_process.append( (acc, ledgerSeq, ledgerHash, ac['nodedata'], proof) )

                                for acc, ls, lh, nd, proof in to_process:
                                    self.process_as_node(acc, ls, lh, nd, proof)
                            
                            
                        
                        if message.ledgerHash in self.ledgers_waiting_on_ledgers:
                            waiting_set = self.ledgers_waiting_on_ledgers[message.ledgerHash]
                            # reprocess all waiting tx in all ledgers in waiting set
                            print("RECIVED LWOL: " + to_hex(message.ledgerHash))
                            for lh in waiting_set:
                                if lh in self.ledger_seq:
                                    reprocess_waiting(self.ledger_seq[lh], lh)
                            del self.ledgers_waiting_on_ledgers[message.ledgerHash]

                        reprocess_waiting(message.ledgerSeq, message.ledgerHash)


                    elif message.type == ripple_pb2.TMLedgerInfoType.liAS_NODE:
                        print("liAS_NODE")

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
                            print("AS_NODE received but contained no accounts we are watching")
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
                            print("account state was not part of a ledger we know of adding wanted ledger " + to_hex(message.ledgerHash))
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
                    #print('get object by hash: -------')
                    #print(message)
                    #print('-----------')

                if message_type == 30: #Transaction
                    #wait for at least one validation before we start wanting tx
                    if self.last_ledger_seq_no == -1:
                        continue

                    
                    #print('mtTransaction: ' + to_hex(SHA512HP(b'TXN\x00', message.rawTransaction))
                    

                    # filter cheaply before parsing 
                    found = False
                    for acc in self.accounts:
                        if message.rawTransaction.find(self.accounts[acc]['raw']):
                            found = True
                            break

                    if not found:
                        continue

                    tx = parse_stobject(message.rawTransaction, False)
                     
                    if tx:
                        for acc in self.accounts:
                            if self.accounts[acc]['raw'] == tx['Account'] or 'Destination' in tx and self.accounts[acc]['raw'] == tx['Destination']:

                                account = self.accounts[acc]

                                txid = SHA512HP(b'TXN\x00', message.rawTransaction)
                                if txid in self.accounts[acc]['wanted_tx']:
                                    break


                                seq = tx['Sequence']
                                #if int(to_hex(txid[0:2]), 16) % 20 == 0:
                                #    print("dropping tx " + to_hex(txid) + " for testing, seq=" + str(seq))
                                #    continue 

                                if 'Destination' in tx and account['raw'] == tx['Destination']:
                                    seq = -1

                                account['wanted_tx'][txid] = {
                                    "ledger_seq_no_at_discovery": self.last_ledger_seq_no,
                                    "max_ledger_seq_no": tx['LastLedgerSequence'],
                                    "aggression": 3
                                }
                                #print('TX: ' + encode_xrpl_address(tx['Account']) + "[W"+str(len(account['wanted_tx']))+" D"+str(len(account['dropped_tx']))+"]" + ", " + str(tx['Sequence']) + " {" + str(self.last_ledger_seq_no) + "}  " + to_hex(txid))
                                break
            
                if message_type == 15: #(mtEndpoints)
                    #print('mtEndpoints')
                    new_ips = set()
                    for endpoint in message.endpoints_v2:
                        ip = endpoint.endpoint.replace('[::', '').replace('ffff:', '').replace(']', '')
                        if re.match(r'^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}$', ip) != None:
                            if not ip in self.peers:
                                self.peers.add(ip)
                                new_ips.add(ip)
                
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
                    if signing_key in config['UNL'] and not signing_key in validations[ledger_hash]:
                        validations[ledger_hash][signing_key] = ledger_seq
                   

                    #print(to_hex(message.validation))

                    #print( "PK in UNL? " + str( (signing_key in UNL) ) )

                    if len(validations[ledger_hash]) < len(self.config['UNL']) * 0.8:
                        continue
                    

                    # execution to here indicates the ledger is validated and we want to make our request now
                    #time.sleep(4) #ensure everyone has the ledger on file


                    if self.last_ledger_seq_no >= ledger_seq:
                        continue


                    self.last_ledger_seq_no = ledger_seq
                    self.last_ledger_hash = ledger_hash
                
                    print("mtVALIDATION ... " + str(len(validations[ledger_hash])) + "/" + str(len(self.config['UNL'])) + " UNL peers have validated - ledger = " + str(ledger_seq))
                    self.request_wanted_tx()

                    print("requesting ledger " + str(ledger_seq) + " hash = " + to_hex(ledger_hash)) 
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
                        print("REQUESTING LEDGER seq: " + str(ls))
                    
                    for lh in self.ledgers_waiting_on_ledgers:
                        if not lh in already_requested:
                            gl = ripple_pb2.TMGetLedger()
                            gl.ledgerHash = lh
                            gl.queryDepth = 1
                            gl.itype = ripple_pb2.TMLedgerInfoType.liBASE
                            self.send_rand_peer(encode_peer_message('mtGetLedger', gl))
                            print("REQUESTING LWOL hash: " + to_hex(lh))

                    # request AS_ROOT every 5 ledgers
                    if not ledger_seq % 5 == 0:
                        before_continue()
                        continue

                    for acc in self.accounts:

                        account = self.accounts[acc]
                        requested_node = account['asroot_key']

                        print('requesting node: ' + requested_node)
                        # now request the account state info
                        gl = ripple_pb2.TMGetLedger()
                        gl.ledgerHash = ledger_hash
                        gl.ledgerSeq = ledger_seq
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

