# XRPL UltraLite
## What is this?
A node that connects to the XRPL with a tiny footprint.

## Usage
python3 ultralite.py rMyAccountOfInterest ... [ rMoreAccountsOfInterest ]

## Output
Depending on the config in the top of ultralite.py you will either receive transactions affecting your accounts of interest in a folder of the account's name under the current working directory (where you ran the program from) or to stdout.

## Output format
If you are outputing to files you will see filename of the form:
```
l<ledger seq number>-<account>-<account seq number>-<tx hash>```
Inside each of these is json in the following form:
```json
{
'ver': 1.1,
'ledger': 52773555,
'txid': '2ca7603b6f0dd2aeaa80e93ef28a42e35e8563855847e1331ef40f6a9718b02f',
'tx': { /* standard transaction fields */ },
'metadata': { /* standard meta data fields */ }
}
```
If you are outputing to stdout you will just receive the json as it becomes available to the node in a constant stream.

## How does it work?
The node connects as a peer into the XRPL mesh network and listens to Validation messages from its UNL. The node can request raw XRPL serialized objects from its peers using a recently closed ledger as a reference point. These objects can be trivially verified for integrity, meaning you do not need to trust the peer/s to whom your peer is connected. The serialized objects are parsed and any information present on the ledger is thereby available to the ultralite node. 

## Things to note
1. The node searches from the current time backwards and forwards in the network state for transactions affecting the accounts you have told it to watch. This is to help you fill gaps if your node is offline for some period of time, however this may also be annoying if you are expecting only new/fresh transactions. An easy way to filter is simply look at `ledger` in each json packet and discard old ledger numbers. 

2. `delivered_amount` is not present in transaction metadata unless it is actually part of the binary data in the ledger. You can reconstruct `delivered_amount` by looking at the Final amounts vs the Previous amounts.

## What might you use this for?
Small devices / IoT devices that need BFT access to the XRPL are good candidates, however application software that doesn't want to rely on a third party's RippleD nodes is just as good a use-case.

## Additional Trust Assumptions
Trust assumptions are the same as full XRPL nodes except the following:
* You assume your UNL will never collectively validate an invalid ledger.
