from copy import deepcopy
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from hashes import hashSHA1
from typing import Dict, List
from User import users_state, users_list, User, UserState
from Transaction import Transaction, create_signed_transaction
import time
import progressbar as pb
import timeit
import sys
import multiprocessing as mp
from multiprocessing import Process, Event
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


ZIMCOIN_REWARD = 10000

processors = mp.cpu_count()

found = False


class Block:
    def __init__(self, previous: bytes, height: int, miner: bytes, transactions: List[Transaction], timestamp: int, difficulty: int, block_id: bytes, nonce: int):
        self.difficulty = difficulty
        self.miner = miner
        self.transactions = transactions
        self.timestamp = timestamp
        self.block_id = block_id
        self.nonce = nonce
        self.previous = previous
        self.height = height

    """
    Previous user states: 

    {
        address: UserState,
        address2: UserState,
        ,
        .
        .
        .
    }
    
    """

    def verify_and_get_changes(self, difficulty: int, previous_user_states: Dict[str, UserState]) -> Dict[str, UserState]:
        """
        Method that when called verifies all the transactions of the block,
        the POW of the block, and then performs the changes in the UserStates.
        """
        self.verificate_pow()
        if difficulty != self.difficulty:
            raise Exception('Incorrect difficulty')
        self.check_correct_block_id()
        assert len(self.miner) == 20
        next_user_states = deepcopy(previous_user_states)
        total_fee = 0
        for transaction in self.transactions:
            if(transaction.sender_hash in next_user_states and transaction.recipient_hash in next_user_states):
                pass
            elif transaction.sender_hash not in next_user_states:
                next_user_states[transaction.sender_hash] = UserState(0, -1)
            else:
                next_user_states[transaction.recipient_hash] = UserState(0, -1)

            transaction.verify(next_user_states[transaction.sender_hash].balance,
                               next_user_states[transaction.sender_hash].nonce)

            # Change the previous_user_states object. As it will be changed inside the method, it will
            # also be changed outside of the method
            transaction.change_user_state(
                next_user_states[transaction.sender_hash], next_user_states[transaction.recipient_hash])

            total_fee += transaction.fee

        try:
            next_user_states[self.miner].balance += ZIMCOIN_REWARD + total_fee
        except KeyError:
            next_user_states[self.miner] = UserState(0, -1)
            next_user_states[self.miner].balance = ZIMCOIN_REWARD + total_fee
        # The object will be changed
        return next_user_states

    def get_changes_for_undo(self, user_states_after: Dict[str, UserState]) -> Dict[str, UserState]:
        next_user_states = deepcopy(user_states_after)
        total_fee = 0
        for transaction in self.transactions:
            if(transaction.sender_hash in next_user_states and transaction.recipient_hash in next_user_states):
                pass
            elif transaction.sender_hash not in next_user_states:
                next_user_states[transaction.sender_hash] = UserState(0, -1)
            else:
                next_user_states[transaction.recipient_hash] = UserState(0, -1)

            # Change the previous_user_states object. As it will be changed inside the method, it will
            # also be changed outside of the method
            transaction.undo_user_state(
                next_user_states[transaction.sender_hash], next_user_states[transaction.recipient_hash])

            total_fee += transaction.fee

        try:
            next_user_states[self.miner].balance -= (
                ZIMCOIN_REWARD + total_fee)
        except KeyError:
            raise Exception('Key not found in dict: This should not happen!! ')

        return next_user_states

    def compute_block_id(self):
        """
        This is a simple method to compute the block_id of the block
        """
        digest = hashes.Hash(hashes.SHA256())
        if(self.previous):
            digest.update(self.previous)
        if type(self.miner) == type('str'):
            self.miner = bytes.fromhex(self.miner)
        digest.update(self.miner)

        for transaction in self.transactions:
            digest.update(transaction.txid)

        digest.update(Transaction.littleEndian(self.timestamp))
        digest.update(Transaction.littleEndian16Bytes(self.difficulty))
        digest.update(Transaction.littleEndian(self.nonce))

        return digest.finalize()

    def check_correct_block_id(self) -> None:
        if self.block_id != self.compute_block_id():
            raise Exception('Block ids do not match!')

    def verificate_pow(self):
        target = 2 ** 256 // self.difficulty
        block_endian = int.from_bytes(self.block_id, 'big', signed=False)
        if block_endian > target:
            raise Exception("Invalid proof of work")


def _mine_block(block: Block, final_nonce, found_event: Event, cutoff_time: int) -> None:
    """
    This is the internal method that is parallelized in order to run as many processes
    of this as possible. This is called form the method mine_block(), and tries to find
    the correct nonce for the block. 
    """

    while time.time() < cutoff_time:
        block.nonce = random.randint(0, 2**64-1)
        block.block_id = block.compute_block_id()
        try:
            block.verificate_pow()
            if final_nonce.value is None:
                final_nonce.value = block.nonce
            found_event.set()
            return None
        except Exception as e:
            pass
    found_event.set()
    return None


def mine_block(previous: bytes, height: int, miner: bytes, transactions: List[Transaction], timestamp: int, difficulty: int, cutoff_time: int) -> 'Block':
    """
    Produce a nonce that is such that the check_correct_block_id and the verificate_pow() both are correct.
    It spawns several parallel processes to try to find that nonce
    """
    print('============================ \n \n \n ============================')
    manager = mp.Manager()
    final_nonce = manager.Value('i', None)
    # Declare a new instance of a block, and change the nonce until it produces a correct block_id

    block = Block(miner=miner, transactions=transactions, timestamp=timestamp,
                  block_id=None, nonce=0, previous=previous, height=height, difficulty=difficulty)
    processes: List[Process] = []

    found_event = Event()
    for _ in range(processors):
        process = Process(target=_mine_block, args=(
            block, final_nonce, found_event, cutoff_time))
        processes.append(process)

    for process in processes:

        process.start()

    found_event.wait()

    for process in processes:
        process.terminate()

    for process in processes:
        process.join()
    print('============= END =============== \n \n \n ============================')
    if final_nonce.value is not None:
        block.nonce = final_nonce.value
        block.block_id = block.compute_block_id()
        return block
    else:
        return None
