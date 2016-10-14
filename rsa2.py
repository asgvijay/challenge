#from Crypto.Hash import SHA256 # for 
from Crypto.PublicKey import RSA # for creating keys
from Crypto import Random # to create random generator
import hashlib # for hashing user input
import sys # for argument access
import os
from objdict import ObjDict
import json


# Ensure 2 arguments. 
# If >2 or <2 arguments, print error and exit
if len(sys.argv) != 2:
    print 'Incorrect number of arguments. Please try again.'
    exit()

# create a new hash for use with user input
sha_256 = hashlib.sha256()
sha_256.update(sys.argv[1])
hash_input = sha_256.hexdigest()

# create unique directory for each user input
# if directory does not exist, we create the directory
# and change our location to the newly created directory
if not os.path.exists(hash_input):
    os.mkdir(hash_input)
    os.chdir(hash_input)
# if the directory already exists, we change to the existing
# directory and access the JSON file
else:
    os.chdir(hash_input)
    jData = open('datafile', 'r')  #open JSON file for reading
    load_j_data = json.load(jData) #parse JSON data
    #print the properties of the data
    # NOTE: can print in one line of code, but due to unorderded mappings
    # inherent in JSON, the output is not ordered as specified in the challenge.
    # To match output of challenge, three separate print calls are made.
    # Better practice would be print json.dumps(load_j_data['properties'], indent=4) 
    print json.dumps(load_j_data['properties']['message'], indent=4) 
    print json.dumps(load_j_data['properties']['signature'], indent=4)
    print json.dumps(load_j_data['properties']['pubkey'], indent=4) 
    # close file and exit the program
    jData.close() 
    exit() 

# create a new RSA key pair using a random_generator    
random_generator = Random.new().read
key = RSA.generate(1024, random_generator)

publickey = key.publickey() # get public key
pubKeyFile = open('./pubKey', 'w+') 
print >> pubKeyFile, publickey.exportKey() # write public key to new file

signature = key.sign(hash_input, '') #create new signature from user input


# Create and populate an object for dumping into JSON
# Each property within the data object that is set equal to ObjDict()
# is an object that contains its own properties
data = ObjDict()
data ['$schema'] = 'http://json-schema.org/draft-04/schema#'
data ['title'] = 'Signed Identifier'
data ['description'] = 'Schema for a signed identifier'
data ['type'] = 'object'
data ['required'] = ['message', 'signature', 'pubkey']
data ['properties'] = ObjDict()
data.properties.message = ObjDict()
data.properties.message.type = sys.argv[1]
data.properties.message.description = "original string provided as the input to your app"
data.properties.signature = ObjDict()
data.properties.signature.type = signature
data.properties.signature.description = "RFC 4648 compliant Base64 encoded cryptographic signature of the input, calculated using the private key and the SHA256 digest of the input"
data.properties.pubkey = ObjDict()
data.properties.pubkey.type = publickey.exportKey() 
data.properties.pubkey.description = "Base64 encoded string (PEM format) of the public key generated from the private key used to create the digital signature"

# print the content of data in JSON format
print json.dumps(data.properties, indent=4)

# dump the info from data object into a json object
json_data = json.dumps(data)

# push json object to its own file
jsonFile = open('./datafile', 'w+')
print >> jsonFile, json_data

#close out files
pubKeyFile.close()
jsonFile.close()