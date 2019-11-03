# XRPL UltraLite
## What is this?
A node that connects to the XRPL with a tiny footprint.

## How does it work?
The node connects as a peer into the XRPL mesh network and listens to Validation messages from its UNL. The node can request raw XRPL serialized objects from its peers using a recently closed ledger as a reference point. These objects can be trivially verified for integrity, meaning you do not need to trust the peer/s to whom your peer is connected. The serialized objects are parsed and any information present on the ledger is thereby available to the ultralite node. 

## What might you use this for?
Small devices / IoT devices that need BFT access to the XRPL are good candidates, however application software that doesn't want to rely on a third party's RippleD nodes is just as good a use-case.

## Additional Trust Assumptions
Trust assumptions are the same as full XRPL nodes except the following:
* You assume your UNL will never collectively validate an invalid ledger.
