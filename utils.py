import socket
import threading
import json
import sys
import random

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

# here we will save registered users in the format: user_id -> { "public_key_pem": bytes }
USER_DB = {}

# here we will save a list of messages that each user gets, in the format: user_id -> list of message envelopes (dict)
MESSAGE_QUEUE = {}    

# store OTP codes for users who are *not yet* in USER_DB
OTP_CODES = {}        # user_id -> 6-digit code (string)

# users that has passed OTP but not yet called register
VERIFIED_USERS = set()

# user_ids currently logged in
ONLINE_USERS = set()  

# server's permanent EC public and private keys
SERVER_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.public_key()

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000

PHONE_NUM_LENGTH = 2