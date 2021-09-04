import sys
import time

import tornado

from miner import Miner
from node import Node
from connections import run_server, remote_connection
from secret import SERVER_ADDRESS

MINER_ADDRESS = 'db82f482cdf4922fa2c957dc7c997c48bf0c12ba'

if __name__ == "__main__":
    if len(sys.argv) == 1:
        REMOTE_NODES = [
            SERVER_ADDRESS]
        print('Starting sqlite DB...')
        node = Node.start("./blocks.sqlite").proxy()
        print('Node started')
        miner = Miner.start(node, MINER_ADDRESS).proxy()
        print('Miner started')

        for remote in REMOTE_NODES:
            remote_connection(node, remote)
        miner.start_mining()
        print('Started mining!!!')

        tornado.ioloop.IOLoop.current().start()
    elif sys.argv[1] == 'server':
        PORT = 46030
        REMOTE_NODES = []
        node = Node.start("./blocks.sqlite").proxy()
        miner = Miner.start(node, MINER_ADDRESS).proxy()
        miner.start_mining()
        run_server(node, PORT)
    else:
        print("Unknown command")
