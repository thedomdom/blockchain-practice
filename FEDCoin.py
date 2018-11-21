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

    def verify_inputs(self, blockchain, block_addition=False):
        # Check if referenced inputs are UTXOs and if the sender is owner
        # Note that the blockchain object is required for this check.

        for input in self.inputs:
            # check if referenced inputs is UTXO
            if input not in blockchain.UTXOs.keys():
                return False
            # Check if referenced input is used in another transaction
            # which is yet part of the mempool.
            # In case a new block is added, this is not necessary
            # (this just for the creation of new transactions,
            # so that less get rejected).
            if not block_addition:
                if input in blockchain.mempool_UTXOs.keys():
                    return False
            # check if referenced inputs is owned by sender of transaction
            parent_block = blockchain.chain[blockchain.UTXOs[input]]

            if parent_block.get_output_by_id(input).recipient != self.sender:
                return False

        # If all checks went fine, return True
        return True

    def verify_sum(self, blockchain):
        # Check if the value of the inputs matches the value
        # the outputs.

        # Get the value of the inputs
        sum_inputs = 0.0
        for input in self.inputs:
            sum_inputs += float(blockchain.get_UTXO_by_id(input).value)
        # Get the value of the outputs
        sum_outputs = 0.0
        for outputs in self.outputs.values():
            sum_outputs += float(outputs.value)
        # Check if input value equals output value
        if sum_inputs == sum_outputs:
            return True
        else:
            return False

    def verify_transaction(self, blockchain, block_addition=False):
        # Run through all checks on the Transaction level

        if self.verify_transaction_signature() and \
                self.verify_transaction_id() and \
                self.verify_inputs(blockchain, block_addition) and \
                self.verify_sum(blockchain):
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


class Block:
    def __init__(self, transactions, previous_hash, timestamp=None, nonce=None):

        # If timestamp is empty, this indicates the creation of a 'real'
        # new block.
        if timestamp is None:
            self.timestamp = time()
        else:
            self.timestamp = timestamp

        self.previous_hash = previous_hash

        # OrderedDict
        # Transactiom.id:Transaction
        self.transactions = transactions

        # If nonce is empty, this indicates the creation of a 'real'
        # new block. (Goes hand in hand with timestamp)
        if nonce is None:
            self.nonce = 0
        else:
            self.nonce = nonce

        # Mapping to get efficient access to an TransactionOutput
        # The mapping doesn't contain any additional info,
        # so it is not part of the actual block information.
        # This means it is not used to create the hash later on.
        self.output_transaction_mapping = self.create_output_transaction_mapping()

        self.id = hash_stuff(self.odict_block())

    def odict_block(self):
        # Creates an OrderedDict of the Block info that is
        # used to calculate the hash.

        # Create an OrderedDict of all transactions
        # by looping through the set of Transactions
        # and converting them each to an OrderedDict.
        # Put all the OrderedDict of the Transactions then
        # into one large OrderedDict.
        transaction_odict = OrderedDict()
        for transaction in self.transactions.values():
            transaction_odict[transaction.id] = transaction.get_full_odict()

        block_odict = OrderedDict({'timestamp': self.timestamp,
                                   'transactions': transaction_odict,
                                   'previous_hash': self.previous_hash,
                                   # Note that the next line --as mentioned--
                                   # does not need to be part of the OD.
                                   # 'output_transaction_mapping': self.output_transaction_mapping,
                                   'nonce': self.nonce})
        return (block_odict)

    def get_full_odict(self):
        # Return the full OrderedDict of the
        # block (including the Hash)

        response = self.odict_block()
        response['id'] = self.id
        return response

    def create_output_transaction_mapping(self):
        # Creates the output_transaction_mapping.
        # Returns an OrderedDict of with
        # TransactionOutput.id:Transaction.id
        # So calling output_transaction_mapping[some_ta_id]
        # returns the id of the Transaction which contains this
        # specific output.

        output_transaction_mapping = OrderedDict()
        for transaction_id, transaction in self.transactions.items():
            for output_id in transaction.outputs.keys():
                output_transaction_mapping[output_id] = transaction_id
        return output_transaction_mapping

    def get_output_by_id(self, output_id):
        # Utilizes the output_transaction_mapping.
        # Returns the TransactionOutput for a given
        # TransactionOutput.id.

        transaction = self.transactions[self.output_transaction_mapping[output_id]]
        return transaction.outputs[output_id]

    def verify_coinbase_transaction(self, blockchain):
        # Verify the correctness of the coinbase transaction.

        # The coinbase transaction is alway the first transaction in a block
        coinbase_transaction = next(iter(self.transactions.values()))

        # Check if the sender is equal to 'coinbase'
        if coinbase_transaction.sender != 'coinbase':
            return False

        # Check if the reward is correct
        parent_height = len(blockchain.chain) - 1
        correct_reward = blockchain.initial_block_reward * (1 / 2) ** ((parent_height + 1) //
                                                                       blockchain.half_time_in_blocks)
        coinbase_output = next(iter(coinbase_transaction.outputs.values()))
        if coinbase_output.value != correct_reward:
            return False

        # Check if the there is only one output
        if len(coinbase_transaction.outputs) != 1:
            return False

        # Check if the id of the coinbase transaction is right
        if not coinbase_transaction.verify_transaction_id():
            return False
        return True

    def verify_block(self, blockchain):
        # Check the correctness of the entire block

        # Verify coinbase transaction
        if not self.verify_coinbase_transaction(blockchain):
            return False

        # Verify the other transactions
        trans_counter = 0
        for transaction in self.transactions.values():
            # Skip the first transaction since this is
            # the coinbase transaction.
            if trans_counter > 0:
                if not transaction.verify_transaction(blockchain, True):
                    return False
            trans_counter += 1
        # At least one transaction in addition to the coinbase
        # transaction must be part of each block
        if trans_counter == 0:
            return False

        # If there are more transactions than allowed, reject the block
        if trans_counter > \
                blockchain.max_block_size_in_transactions + 1:
            return False

        # Verify the hash of the block
        if self.id != hash_stuff(self.odict_block()):
            return False

        # Verify difficulty
        if self.id[:blockchain.initial_difficulty] != \
                '0' * blockchain.initial_difficulty:
            return False
        return True


class Blockchain:
    initial_difficulty = 4
    initial_block_reward = 50
    half_time_in_blocks = 10
    max_block_size_in_transactions = 5

    def __init__(self):
        self.chain = OrderedDict()  # OD containing the blocks of the chain -- Block.id : Block
        self.UTXOs = OrderedDict()  # OD with UTXOs -- TransactionOutput.id : Block.id
        self.mempool = OrderedDict()  # OD with transactions -- Transaction.id:Transaction
        self.mempool_UTXOs = OrderedDict()  # OD with UTXOs used in mempool -- TransactionOutput.id:Transaction.id
        self.pow = 0  # pow of the chain
        self.add_genesis_block()

    def create_genesis_block(self):
        # Create Genesis Transaction
        genesis_pub_key = '3059301306072a8648ce3d020106082a8648ce3d030107034200043f3bd6d16ce4bde95a8237170aaa106388485498234a3dca5d0c273d907c03c3e72017bec13cf6e893e96da0f9d6c7037c79b40cb006aff12ae88adae1b0bb7e'

        genesis_output = TransactionOutput(genesis_pub_key, self.initial_block_reward, 0, timestamp=0)
        genesis_transaction = Transaction('coinbase', ['coinbase_UTXO'],
                                          OrderedDict({genesis_output.id: genesis_output}), 0)

        # Create Genesis Block as block object
        genesis_block = Block(OrderedDict({genesis_transaction.id: genesis_transaction}), 'genesis', 0, 51473786)

        # Add the Genesis Block
        return (genesis_block)

    def add_block(self, new_block):
        # The first block has to be the genesis
        if not self.chain:
            if new_block.__eq__(self.create_genesis_block()):
                self.chain[new_block.id] = new_block
                # Update pow of the chain
                self.pow = self.initial_difficulty * len(self.chain.keys())
                # Update UTXOs
                self.update_UTXOs(new_block)
                return True
            else:
                return False
        else:
            # Check if block has correct previous_hash and if new block is valid
            if self.get_last_block().id == new_block.previous_hash and \
                    new_block.verify_block(self):
                self.chain[new_block.id] = new_block
                # Update pow of the chain
                self.pow = self.initial_difficulty * len(self.chain)
                # Update UTXOs
                self.update_UTXOs(new_block)
                # Update mempool
                self.update_mempool(new_block)

                return True
            else:
                return False

    def update_UTXOs(self, new_block):
        # After a block has been added to the chain
        # the UTXOs are updated

        # remove all referenced inputs
        for transaction in new_block.transactions.values():
            for inp in transaction.inputs:
                if inp != 'coinbase_UTXO':
                    del (self.UTXOs[inp])

            for output_key in transaction.outputs.keys():
                self.UTXOs[output_key] = new_block.id

    def update_mempool(self, new_block):
        # After a block has been added to the chain remove
        # its transactions from the chain's mempool

        # Remove the transactions from that block in the mempool
        for transaction_id, transaction in new_block.transactions.items():
            # Coinbase transaction is not in mempool, therefore make sure the trans to remove is even part of the mempool before removing it. Also if transaction was previously uknown for the node (possible). Note that in the update_UTXOs() function we do not have to check for that since the referenced UTXO has to be part of the chains UTXO OrderedDict(), otherwise the block couldn't be accepted by the chain.
            if transaction_id in self.mempool.keys():
                del (self.mempool[transaction_id])
                # Delete corresponding input UTXOs as well
                for input in transaction.inputs:
                    del (self.mempool_UTXOs[input])

    def add_genesis_block(self):
        # Create and add the genesis to the chain

        genesis_block = self.create_genesis_block()
        self.add_block(genesis_block)

    def get_UTXO_by_id(self, UTXO_id):
        # Returns the UTXO for a given UTXO_id

        return (self.chain[self.UTXOs[UTXO_id]].get_output_by_id(UTXO_id))

    def get_last_block(self):
        # Returns the most recent added block of the chain

        last_id = next(reversed(self.chain))
        return (self.chain[last_id])

    def process_transaction(self, transaction):
        # Check if transaction is valid given the current state of the chain

        if transaction.verify_transaction(self):

            # Add transaction to the mempool
            self.mempool[transaction.id] = transaction
            # Add UTXOs of the transaction to the OD of used UTXOs in the mempool
            for input in transaction.inputs:
                self.mempool_UTXOs[input] = transaction.id

            return (True)

        else:
            return (False)

    def create_coinbase_transaction(self, public_key_receiver):
        # Creates the coinbase transaction for the next block

        # Since we start at zero for measuring the height
        parent_height = len(self.chain) - 1

        # '//'  performs a floor division, i.e. 5 // 2 = 2, whereas 5 / 2 = 2.5
        # ** is the power operator, i.e. 5**2 = 25
        coinbase_reward = self.initial_block_reward * (1 / 2) ** ((parent_height + 1) \
                                                                  // self.half_time_in_blocks)
        coinbase_output = TransactionOutput(public_key_receiver, coinbase_reward, \
                                            0, timestamp=0)
        coinbase_transaction = Transaction('coinbase', ['coinbase_UTXO'], \
                                           OrderedDict({coinbase_output.id: coinbase_output}), 0)
        return (coinbase_transaction)

    def mine_block(self, public_key_receiver_coinbase_transaction):
        # Creates a valid block from the transactions in the mempool.
        # public_key_receiver_coinbase_transaction should be a public key belonging
        # to the miner of the block.

        # Mine only if the mempool is not empty
        if self.mempool:

            # Block construction
            transactions_odict = OrderedDict()

            # Create the Coinbase transaction
            coinbase_transaction = \
                self.create_coinbase_transaction(public_key_receiver_coinbase_transaction)

            transactions_odict[coinbase_transaction.id] = coinbase_transaction

            normal_transaction_counter = 0
            for transaction_id, transaction in self.mempool.items():
                # If max allowed # of transactions are collected
                if normal_transaction_counter >= self.max_block_size_in_transactions:
                    break  # Get out of the for-loop
                transactions_odict[transaction_id] = transaction
                normal_transaction_counter += 1

            candidate_block = Block(transactions_odict,
                                    list(self.chain.values())[len(self.chain) - 1].id)
            # prev hash

            # Solve Proof of work
            candidate_block_odict = candidate_block.odict_block()
            candidate_block_id = hash_stuff(candidate_block_odict)

            # Check if the first #initial_difficulty figures of the hash are equal to 0
            # if not  continue mining
            # Note: Mining is done on the OrderedDict version
            while not candidate_block_id[:self.initial_difficulty] == \
                      '0' * self.initial_difficulty:
                candidate_block_odict['nonce'] = candidate_block_odict['nonce'] + 1
                candidate_block_id = hash_stuff(candidate_block_odict)

            # If mining was successful, put the solution into the Block() object
            candidate_block.nonce = candidate_block_odict['nonce']
            candidate_block.id = candidate_block_id

            # Add block to the chain
            return (candidate_block)

        # If there is no transaction in the mempool no block can be mined
        return (None)
