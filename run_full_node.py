from IPython.core.debugger import set_trace
from flask import Flask, request
from threading import Event, Thread
from FEDCoin import *
import json
import time

## New (4_5) run 1 -- (THIS ENTIRE CLASS IS NEW)
class MiningLoopThread(Thread):
    def __init__(self, pause_mining_event, full_node):
        # Creates a MiningLoopThread instance which inherits
        # from the Thread class. It is important to note,
        # that all external parameters that should also be
        # known by this Thread have to be assigned to this
        # Thread as well. I.e. in our case this is the pause_mining_event
        # and the full_node.
        self.pause_mining_event = pause_mining_event
        self.full_node = full_node

        # After the parameters are passed to the Thread
        # it calls the constructor of the parent class
        Thread.__init__(self)

    def run(self):
        # This defines (or runs) the process we want to run parallel
        # , i.e. the Mining loop

        # We run this loop forever
        while True:
            # Start mining only if the mempool of the
            # full_node's current primary chain is non empty
            # and if pause_mining_event is not set
            if self.full_node.get_primary_chain().mempool and not self.pause_mining_event.is_set():
                print('Start mining Block.')

                # This triggers the actual mining
                mined_block = self.full_node.get_primary_chain().mine_block(self.full_node.public_key_receiver_coinbase_transaction,self.pause_mining_event)
                if mined_block is not None:

                    # Add the mined block to the primary chain
                    # and also add its id to the list of known ids

                                  # Add the backuped_chain to the chains to enable emergence of
                    # competing forks.
                    backup_chain = copy.deepcopy(self.full_node.get_primary_chain())
                    test_dummy = self.full_node.get_primary_chain().add_block(mined_block)
                    if test_dummy:
                       self.full_node.add_backuped_chain(backup_chain)

                    self.full_node.seen_block_ids.append(mined_block.id)


                    # This is more or less debugging output:
                    print('Successfully mined block with id ' + str(mined_block.id[:8]) + '...')
                    print('Current prim. chain length ' + str(len(self.full_node.get_primary_chain().chain)) + '.')
                    print('Current mempool size ' + str(len(self.full_node.get_primary_chain().mempool.keys())) + '.')

                    # In case a neighbor went offline after registering
                    # the propagate_block method will throw and error.
                    # Therefore we need the try: ... except: clause.
                    try:
                        # Propagate the block to neighbors
                        self.full_node.propagate_block(mined_block.id)
                    except:
                        pass

            # Note that the event is cleared in the process_incoming_block routine when processing is finished.

            # This is entered if pause_mining_event is set.
            elif self.pause_mining_event.is_set():
                print('Primary chain changed, mining paused.')
                # Sleep is not necessary but it's easier this way, i.e. otherwise
                # mining might restart to quickly then stop again etc.
                time.sleep(5)

            # This is entered if the primary chain's mempool is empty
            else:
                print('Nothing to mine at the moment, mining paused.')
                # Sleep is not necessary but it's easier this way
                time.sleep(5)



# Creating an instance of the FullNode class. This is THE FullNode in
# this example.
full_node = FullNode()

# Starting Flask
app = Flask(__name__)

# Initialize Event
PAUSE_MINING_EVENT = Event()

## New (4_5) run 2
# Initialize MiningLoop
minig_loop_thread = MiningLoopThread(PAUSE_MINING_EVENT,full_node)

# This is the anchor to call 'get_UTXOs_for_public_key'
# for any external client.
# "/get_UTXOs_for_public_key" defines the path,
# methods=['GET'] defines by which request type this anchor can be called
# Note that request.form['public_key'] is a variable passed within the
# request. The 200 in the return statement just indicates the client
# that everything went fine (i.e. 404 is the code for a well known error).
@app.route("/get_UTXOs_for_public_key", methods=['GET'])
def get_UTXOs_for_public_key():
    # This is the line where the full_node instance calls its method
    # get_UTXOs_for_public_key with the request.form['public_key']
    # argument
    response = full_node.get_UTXOs_for_public_key(request.form['public_key'])
    # Return the response in json format
    return json.dumps(response), 200

@app.route("/register_a_neighbor", methods=['GET'])
def register_a_neighbor():
    # Registers a new neighbor at the full_node

    other_neighbors = full_node.register_a_neighbor(request.form['address'])
    return json.dumps(other_neighbors), 200

@app.route("/post_transaction", methods=['POST'])
def post_transaction():
    # Parses the Transaction Data and makes the full_node
    # process the transaction.

    transaction = Transaction.from_odict(create_odict_from_json(request.get_data()))
    response = full_node.add_transaction_to_mempools(transaction)
    return json.dumps(response), 200

@app.route("/post_block", methods=['POST'])
def post_block():
    block = Block.from_odict(create_odict_from_json(request.get_data()))
    response = full_node.process_incoming_block(block,PAUSE_MINING_EVENT)
    return json.dumps(response), 200

@app.route("/get_list_of_seen_blocks", methods=['GET'])
def get_list_of_seen_blocks():
    response = full_node.get_list_of_seen_blocks()
    return json.dumps(response), 200

@app.route("/get_block_by_id", methods=['GET'])
def get_block_by_id():
    block = full_node.get_block_by_id(request.form['block_id'])
    response = block.get_full_odict()
    return json.dumps(response), 200

# This is a test anchor for hello world
@app.route("/hello_world", methods=['GET'])
def hello_world():
    # Prints hello world to the console and returns
    # hello world.
    # Just for testing!
    print('hello_world')
    return('hello world!')


# This clause is entered if run_full_node.py is executed via the
# console.
# This code can be called via the console i.e:
# python run_full_node.py -p 5001
# If no port is passed the default port 5000 is used.
if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, \
        help='Listening port for the FullNode')

    parser.add_argument('-n','--neighbors', nargs='*', help='Neighbor addresses, i.e. 127.0.0.1:5000')

    ## New (4_5) run 4
    parser.add_argument('-pk','--public_key_file_name', default='public_key.txt', type=str, help='Name of the file containing the public key for the coinbase transactions of the node.')


    # Parse the arguments that are passed when the run_full_node.py
    # is started via the console
    args = parser.parse_args()
    port = args.port
    neighbors = args.neighbors
    ## New (4_5) run 5
    public_key_file_name = args.public_key_file_name

    # Set the full_nodes own address
    ip = '127.0.0.1'
    full_node.address = ip + ':' + str(port)
    print('New Node running on ' + full_node.address)

    ## New (4_5) run 6
    # This opens the public_key_file_name file and reads
    # the public key. then the key is passed to the full_node
    with open(public_key_file_name, 'r') as key_file:
        # Just in case it was pasted with linebreaks
        full_node.public_key_receiver_coinbase_transaction=key_file.read().replace('\n', '')


    # Register as neighbor
    if neighbors is not None:
        for n in neighbors:
            # Add the neighbor to tne nodes own list of neighbors
            full_node.neighbors.append(n)
            # Register at the node as neighbor (i.e. the other node add this node to its list of neighbors as well)
            full_node.register_as_neighbor(n)

        # Initialize the node
        full_node.initialize_node(PAUSE_MINING_EVENT)

    ## New (4_5) run 3
    # Start the mining loop
    minig_loop_thread.start()

    # Run the Flask App
    app.run(host='127.0.0.1', port=port)
