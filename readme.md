#Doc Proofs

##Introduction
Skuchain has developed a protocol for parties to notarize attestations of the state of contracts documents.
This protocol is notable in several regards

1. Partial Transparency of notarized documents
2. Verifiable Encrypted Data fields
3. Integration with automated execution solutions through Interledger support

This protocol is blockchain agnostic. This particular implementation is within the Hyperledger Fabric's Chaincode.

## Purchase Order Example

 Blockchain based proof of purchase order.

 Blockchain technology allow buyers, sellers and financiers to generate independently verifiable proofs of the purchase order though our system.

 When any portion of a purchase order is shared with a new party, the system is designed so that the following verifications can easily made against the data

  - The data is approved by all of the parties
  - That the terms are current and have not been superseded by a more recent version
  - Privacy of underlying business data.


 Proof of Purchase order makes extensive use of cryptographic commitments to data held on other systems. Crytographic commitments have two key properties. They hide the information committed to and they bind to that information such that only the original information can satisfy the commitment.

 Proof of Purchase Order is made up several distinct components inside a distributed ledger
 called Proof Elements.

```

                   Simple Proof of Purchase Order

 +---------------------------------------+
 |             ID                        |
 |         +--------------+              |    Purchase Order Root
 |         |PE:HEAD       |              |    {
 |         |COMMITMENT:   |              |      PE:1 ID
 |         |Purchase      |              |      PE:2 ID
 |         |Order Root    |              |      PE:3 ID
 |         |Sigs: Buyer   |              |    }
 |         |& Seller sig  |              |
 |         +--------------+              |
 |                                       |
 |  +---------------------------------+  |
 |  |   PE:1                          |  |
 |  |   Commitment: Delivery Details  |  |
 |  |   Sigs: Buyer & Seller sig      |  |
 |  +---------------------------------+  |
 |                                       |
 |  +---------------------------------+  |
 |  |   PE:2                          |  |
 |  |   Commitment: Order Amounts     |  |
 |  |   Sigs: Buyer & Seller sig      |  |
 |  +---------------------------------+  |
 |                                       |
 |  +---------------------------------+  |
 |  |   PE:3                          |  |
 |  |   Commitment: Payment Conditions|  |
 |  |   Sigs: Buyer & Seller sig      |  |
 |  +---------------------------------+  |
 +---------------------------------------+
```


 When a modification is sent, a set of transactions introduces a superseding proof
 element into the ledger.

 Anyone with an outdated proof will see that there is the terms have been changed



      Purchase Order with Mod
```
 +-----------------------------------------------------------------------------------------+
 |             ID                                                                          |
 |         +--------------+                                                                |
 |         |PE:HEAD       |                                                                |
 |         |COMMITMENT:   |                                                                |
 |         |Purchase      |                                                                |
 |         |Order Root    |                                                                |
 |         |Sigs: Buyer   |                                                                |
 |         |& Seller sig  |                                                                |
 |         +--------------+                                                                |
 |                                                                                         |
 |  +---------------------------------+                                                    |
 |  |   PE:1                          |                                                    |
 |  |   Commitment: Delivery Details  |                                                    |
 |  |   Sigs: Buyer & Seller sig      |                                                    |
 |  +---------------------------------+                                                    |
 |                                                                                         |
 |  +---------------------------------+              +---------------------------------+   |
 |  |   PE:2                          |              |   PE:2'                         |   |
 |  |   Commitment: Delivery Details  +------------->+   Commitment: Delivery Details  |   |
 |  |   Sigs: Buyer & Seller sig      |              |   Sigs: Buyer & Seller sig      |   |
 |  +---------------------------------+              +---------------------------------+   |
 |                                                                                         |
 |  +---------------------------------+                                                    |
 |  |   PE:3                          |                                                    |
 |  |   Commitment: Delivery Details  |                                                    |
 |  |   Sigs: Buyer & Seller sig      |                                                    |
 |  +---------------------------------+                                                    |
 +-----------------------------------------------------------------------------------------+
```


 If a new Proof element is introduced in to a Purchase Order Proof, the Head element is updated to include a commitment to the new proof element.



                  Purchase Order with Addition
```
    +----------------------------------------------------------------------+
    |             ID                                ID                     |
    |         +--------------+                  +--------------+           |
    |         |PE:HEAD       |                  |PE:HEAD       |           |
    |         |COMMITMENT:   |                  |COMMITMENT:   |           |
    |         |Purchase      +----------------> | Amended Root |           |
    |         |Order Root    |                  |              |           |
    |         |Sigs: Buyer   |                  |Sigs: Buyer   |           |
    |         |& Seller sig  |                  |& Seller sig  |           |
    |         +--------------+                  +--------------+           |
    |                                                                      |
    |  +---------------------------------+                                 |
    |  |   PE:1                          |                                 |
    |  |   Commitment: Delivery Details  |                                 |
    |  |   Sigs: Buyer & Seller sig      |                                 |
    |  +---------------------------------+                                 |
    |                                                                      |
    |  +---------------------------------+                                 |
    |  |   PE:2                          |                                 |
    |  |   Commitment: Order Amounts     |                                 |
    |  |   Sigs: Buyer & Seller sig      |                                 |
    |  +---------------------------------+                                 |
    |                                                                      |
    |  +---------------------------------+                                 |
    |  |   PE:3                          |                                 |
    |  |   Commitment: Payment Conditions|                                 |
    |  |   Sigs: Buyer & Seller sig      |                                 |
    |  +---------------------------------+                                 |
    |                                                                      |
    |                                                                      |
    |                                                                      |
    |                                                                      |
    |                              +---------------------------------+     |
    |                              |   PE:4                          |     |
    |                              |   Commitment: Special Conditions|     |
    |                              |   Sigs: Buyer & Seller sig      |     |
    |                              +---------------------------------+     |
    +----------------------------------------------------------------------+
```

 #Verifying Proofs against the Ledger.
 Verification is done under under a capabilities model.
 A User of the system who wishes to verify a proof must obtain a set of capabilities.
 How this is done is outside the scope of the chaincode.
 A User will first obtain a Root object which is a capability to view all the
 Proof elements. The same system will provide the user with an algorithim for
 generating a commitment. The user generates a commitment from the root object.
 The root object will contain a set of Proof Element Ids and their types
 The user will have the capability to verify against a subset of these proof elements.
 These will beused to contract Purcha6seOrderVerify protocol buffer message and use the PurchaseOrderVerify
 Query transaction against the ledger

 Example of Client Computation
 Response from Capabilties Server= { rootElementProofId = "43125678976", commimtment_alg ="sha256", rootObject:[{id:"1341253",title:"Delivery"},{id:"4659252345",title:"Payment Terms"},{id:"1341253",title:"Item list"}], [{title:"Payment Terms"}, data: *binary*blob*]
 Client computes sha256(rootObject)
 Client computes sha256(data)
 Client generates a PurchaseOrderVerify({43125678976,sha(rootObject)},[{4659252345,sha(data)}])
 If the Proofs are valid the Query tx will return the json of the 43125678976 and 4659252345 elements
 ## Verifcation Diagram

```
 Request a Root Object
   and Purchase Order
                           +------------------------------+
   Clause                   |       Capabilities Server    |
              +---------->  |Validates User Credentials    |
              |             |                              |
              |             |                              |
              |             |                              |
              |             |                              |
              |             |                              |
              |             +------------------------------+
              |                           |
              |                           | Server responds with Root Object,
              |                           | and Purchase Order
  +---------------+                       | And Root Object Id
  | User requires |                       |
  | a Purchase    |                       |
  | Order Proof   |                       |
  |               | <---------------------+
  |               |
  |               |
  +---------------+
         |
         |
         |  User computes the Root Object
         |  commitment and determines which Proof
         |  Elements from the Root Object are
         |  needed to validate the signature
         |
         |
         |
         |
         |
         |
         v
  +------+--------+
  |User composes  |
  |a Purchase     |
  |Order          |  ----------------------------+
  |Verifcation    |                              |
  |TX             |             Send             |
  |               |             Verification     |
  +------+--------+             Transcations     |
         ^                                       |
         |                                       |
         |                                       |
         | Receive Verification                  |
         | Response if all Clauses               |
         | are correct and signed                |
         | OR                                    v
         | Error                           +-----+--------+
         |                                 |              |
         |                                 | Hyperledger  |
         |                                 | Peer         |
         +------------------------------   | Computes     |
                                           | Verfication  |
                                           |              |
                                           |              |
                                           +--------------+
```
