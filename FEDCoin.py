# Import the modules we need
from IPython.core.debugger import set_trace

from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import binascii
from time import time
import random

from collections import OrderedDict
import hashlib
import json
from utils import *


class Wallet:
    def __init__(self, private_key_str=None):
        keypair = self.generate_keypair(private_key_str)
        self.private_key = keypair['private_key']
        self.public_key = keypair['public_key']

    def generate_keypair(self, private_key_str):
        # If this is a 'new' wallet, i.e. no private_key_str has been given to the constructor
        # --> Create a private key
        if private_key_str is None:
            # Generate the private key (in here the randomness takes place)
            private_key = ECC.generate(curve='P-256')
        else:
            # In case this is a wallet for a specific private_key
            # read the private key in string format.
            # binascii.unhexlify(x) converts x which is in hexadecimal format into a binary format
            private_key = ECC.import_key(binascii.unhexlify(private_key_str))

        # We return a dictionary with private and public key
        keypair = {
            'private_key': binascii.hexlify(private_key.export_key(format='DER')).decode('utf8'),
            'public_key': binascii.hexlify(private_key.public_key().export_key(format='DER')).decode('utf8')
        }
        return keypair


class Transaction:
    def __init__(self, sender_pub_key, inputs, outputs, timestamp=None, signature=None, transaction_id=None):
        # Note: This is somehow similar to the initialization
        # of TransactionOutput, except of the fact that there
        # are different 'fields' in the Transaction class.
        if timestamp is None:
            self.timestamp = time()  # include, to not have a hash collision for similar transactions
        else:
            self.timestamp = timestamp
        self.sender = sender_pub_key
        self.inputs = inputs  # list of IDs referring to UTXOs
        self.outputs = outputs  # OrderedDict with id:TransactionOutput

        # Signature and ID are (re)created when the transaction is signed
        # Note: The coinbase transaction has no signature
        if signature is None:
            self.signature = ''
        else:
            self.signature = signature

        if transaction_id is None:
            self.id = self.hash_transaction()
        else:
            self.id = transaction_id

    def odict_transaction(self):
        # Create an OrderedDict representation
        # We need this to sign it later on, therefore the
        # signature is not included in the OrderedDict

        outputs_odict = OrderedDict()
        for output in self.outputs.values():
            outputs_odict[output.id] = output.get_full_odict()
        transaction_odict = OrderedDict({
            'timestamp': self.timestamp,
            'sender': self.sender,
            'inputs': self.inputs,
            'outputs': outputs_odict})
        return (transaction_odict)

    def hash_transaction(self):
        # Creates a hash of the transaction
        # We need this extra function since we have to
        # add the signature to the OrderedDict  object
        # manually. Otherwise we could simply use the hash_suff()
        # from above directly.

        transaction_dict = self.odict_transaction()
        transaction_dict['signature'] = self.signature
        transaction_string = json.dumps(transaction_dict).encode()
        return hashlib.sha256(transaction_string).hexdigest()

    def get_full_odict(self):
        # We need this to get a full OrderedDict (incl. ID)
        # rerepsentation of a Transaction to enable
        # hashing of blocks on the block-level later on.

        response = self.odict_transaction()
        response['signature'] = self.signature
        response['id'] = self.id
        return response

    def sign_transaction(self, private_key):
        # Sign a transaction using the private_key

        private_key = ECC.import_key(binascii.unhexlify(private_key))
        signer = DSS.new(private_key, 'fips-186-3')
        # h = hashlib.sha256.new(str(self.odict_transaction()).encode('utf8'))
        h = SHA256.new(str(self.odict_transaction()).encode('utf8'))
        self.signature = binascii.hexlify(signer.sign(h)).decode('utf8')
        # When the signature is created the id can be set
        self.id = self.hash_transaction()

    def verify_transaction_signature(self):
        # Check if the transaction signature is valid
        # i.e. does the signature match the Transaction object.
        # Note: This might not make too much sense given the way we
        # create transactions in this tutorial.
        # But in case we get transaction data
        # from a remote point, this is important!

        public_key = ECC.import_key(binascii.unhexlify(self.sender))
        verifier = DSS.new(public_key, 'fips-186-3')
        h = SHA256.new(str(self.odict_transaction()).encode('utf8'))
        try:
            verifier.verify(h, binascii.unhexlify(self.signature))
            return (True)
        # In case the signature is no authentic, the verifier throws a ValueError
        except ValueError:
            return (False)

    def verify_transaction_id(self):
        # Check if the id matched the Transaction content

        if self.id == self.hash_transaction():
            return True

        return False


class TransactionOutput:
    def __init__(self, recipient_public_key, value, random_val=None, id=None, timestamp=None):
        # Timestamp is none if new output is created,
        # not none if old one is referenced/recreated
        if timestamp is None:
            self.time = time()
        else:
            self.time = timestamp

        # We need the random_val so that each output is guaranteed to be unique, even for same t.
        # I.e. in theory, if two TransactionOutputs (for the same recipient)
        # are generated at the exact same time we still want to be able to distinguish them
        if random_val is None:
            # self.random = 0
            self.random = random.randint(0, 10000000000000)
        else:
            # self.random = 0
            self.random = random_val

        self.recipient = recipient_public_key  # This defines the owner of the coins
        self.value = value  # Simply the value of the output

        # If it's a new transactin, calculate the hash,
        # if it is an existing one, read the hash from the argument given at construction.
        if id is None:
            self.id = hash_stuff(self.odict_transaction_output())
        else:
            self.id = id

    def odict_transaction_output(self):
        # A hash function needs some string as input.
        # To get a string from a TO object (not the entire one)
        # we use a OrderedDict representation which can be converted into a String.

        transaction_output_odict = OrderedDict({
            'time': self.time,
            'random': self.random,
            'recipient': self.recipient,
            'value': self.value
        })
        return (transaction_output_odict)

    def get_full_odict(self):
        # We need this to get a full OrderedDict (incl. ID)
        # representation of the TO in order to enable Transaction
        # hashing on the Transaction level later on.

        response = self.odict_transaction_output()
        response['id'] = self.id
        return response
