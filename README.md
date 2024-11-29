# RSA Powered Connection System

A Python-based implementation of a secure communication system using the RSA encryption algorithm. This system ensures confidentiality, integrity, and authenticity between two clients through a Public Key Distribution Authority (PKDA).

---

## Key Features

1. **RSA Encryption and Decryption**:
   - Secure encryption and decryption of messages using RSA.
   - Implements robust algorithms to ensure secure data transmission.

2. **Public Key Distribution Authority (PKDA)**:
   - Acts as a trusted third party to manage and distribute public keys.
   - Ensures secure exchange of keys and prevents unauthorized access.

3. **Client Communication**:
   - Supports encrypted messaging between two clients.
   - Utilizes nonces and timestamps to ensure message freshness and prevent replay attacks.

4. **Error Handling**:
   - Includes a try-except mechanism to handle communication errors gracefully.

---

## Tech Stack

- **Programming Language**: Python
- **Libraries**:
  - `socket` for networking
  - `Crypto` for RSA implementation
  - `pickle` for serialization
  - `random` for generating nonces
  - `time` and `datetime` for timestamps

---

## System Design

### Files and Components

#### 1. **`client.py`**
This file contains two main classes and a `main()` function.

- **Class: RSA**
  - `Encryption(message, key)`: Encrypts messages using RSA.
  - `Decryption(message, key)`: Decrypts encrypted messages.
  - `RSA_Operation(m, x, n)`: Performs core RSA operations.
  - `RSA_Encode(msg)`: Encodes string messages into ASCII tuples.
  - `RSA_Decode(tup)`: Decodes ASCII tuples into string messages.

- **Class: Client**
  - `__init__(self, client_id, pr_key, pu_key, pkda_pu_key)`: Initializes client with keys.
  - `Generate_msg_for_pkda(client_id)`: Creates messages for requesting public keys from PKDA.
  - `Msg_from_pkda(message)`: Processes responses from the PKDA.
  - `Msg_for_client(client_id, msg, nonce=None)`: Generates encrypted messages for other clients.
  - `Msg_from_client(message)`: Processes messages received from other clients.
  - `Gen_Nonce()`: Generates unique nonces for secure communication.
  - `Res_Nonce(n)`: Responds to nonces for integrity confirmation.
  - `Time()`: Provides timestamps for message validity.
  - `Req_pu_k_from_pkda(pkda_address, m)`: Handles key requests from PKDA.

- **`main()` Function**:
  - Reads key files and initializes client instances.
  - Handles secure communication between two clients using socket programming.

#### 2. **`pkda.py`**
This file contains two main classes and a `main()` function.

- **Class: RSA**
  - Same as the `RSA` class in `client.py`, with an additional function:
    - `gcd(x, y, a, b, c, d)`: Uses the Extended Euclidean Algorithm to calculate the decryption key.

- **Class: PKDA**
  - `__init__(self, mappings, pr_key, pu_key)`: Initializes PKDA with mappings and keys.
  - `Msg_from_client(message)`: Decrypts messages from clients and provides public keys.
  - `Res_Nonce(n)`: Generates unique nonces for communication.
  - `Time()`: Provides timestamps for messages.

- **`main()` Function**:
  - Generates RSA key pairs for clients and PKDA.
  - Establishes a TCP server for key distribution.
  - Handles requests from clients and responds with encrypted public key information.

---

## Workflow

1. **Setup**:
   - PKDA generates RSA keys for clients and itself.
   - Keys are stored in text files.

2. **Client Communication**:
   - Clients request public keys from PKDA.
   - PKDA verifies requests, encrypts public keys, and sends them securely.

3. **Messaging**:
   - Clients exchange encrypted messages using the public keys.
   - Messages include nonces and timestamps for added security.

4. **Error Handling**:
   - If communication fails, the system retries to establish a connection.
