
# Import the modules we need
from IPython.core.debugger import set_trace
import hashlib
import json
from collections import OrderedDict



def hash_stuff(ordered_dict_of_stuff):
    # Creates a SHA-256 hash of a the ordered_dict_of_stuff

    # Create a string representation of the ordered dict
    # (via a json object)
    stuff_string = json.dumps(ordered_dict_of_stuff).encode('utf8')
    # Return the hexadecial 256 bit hast of the string
    return hashlib.sha256(stuff_string).hexdigest()

def create_odict_from_json(json_stuff):
    return json.loads(json_stuff.decode('utf8'), object_pairs_hook=OrderedDict)
