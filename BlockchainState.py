from blocks_test import calculate_sha1_hash, private_key_to_public_key
from cryptography.hazmat.backends import default_backend
from Block import Block
from typing import List, Dict
from User import UserState
import random
from time import sleep, time
from Transaction import create_signed_transaction
from Block import mine_block
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from functools import reduce
from copy import deepcopy

DIFFICULTY_PERIOD = 10


class BlockchainState():
    def __init__(self, longest_chain: List[Block], user_states: Dict[str, UserState], total_difficulty: int) -> None:
        self.longest_chain = longest_chain
        self.user_states = user_states
        self.total_difficulty = total_difficulty

    def calculate_difficulty(self) -> int:
        if len(self.longest_chain) <= DIFFICULTY_PERIOD:
            return 1000
        sleep(0.1)
        total_difficulty_for_period = reduce(
            lambda a, b: a + b.difficulty, self.longest_chain[-10:], 0)

        total_time_for_period = self.longest_chain[-1].timestamp - \
            self.longest_chain[-11].timestamp

        if total_time_for_period == 0:
            return 1200000
        return (total_difficulty_for_period // total_time_for_period) * 120

    def verify_and_apply_block(self, block: Block):

        if block.height != len(self.longest_chain):
            raise Exception('Height not equal to longest chain height!')
        if not self.longest_chain:
            assert block.previous == bytes.fromhex(
                '0000000000000000000000000000000000000000000000000000000000000000'), 'previous block id'
        else:
            if self.longest_chain[-1].block_id != block.previous:
                raise Exception('previous block id')

        if self.longest_chain:
            if block.timestamp < self.longest_chain[-1].timestamp:
                raise Exception(
                    'Timestamp is not greater than past timestamp!')

        changed_states = block.verify_and_get_changes(
            self.calculate_difficulty(), self.user_states)
        self.longest_chain.append(block)
        self.total_difficulty += block.difficulty
        self.user_states.update(changed_states)

    def undo_last_block(self):
        last_block = self.longest_chain.pop()
        print('Current difficulty:', self.total_difficulty)
        print('difficulty to be deleted: ', last_block.difficulty)
        self.total_difficulty -= last_block.difficulty
        print('Now it is: ', self.total_difficulty)
        self.user_states.update(
            last_block.get_changes_for_undo(self.user_states))


def verify_reorg(old_state: BlockchainState, blocks: List[Block]) -> BlockchainState:
    new_state = BlockchainState(deepcopy(
        old_state.longest_chain), deepcopy(old_state.user_states), old_state.total_difficulty)

    goal_height = blocks[0].height

    while new_state.longest_chain[-1].height >= goal_height:
        new_state.undo_last_block()
    for block in blocks:
        new_state.verify_and_apply_block(block)

    assert new_state.total_difficulty > old_state.total_difficulty, 'total difficulty'
    assert new_state.longest_chain[-1].height >= old_state.longest_chain[-1].height, 'Total height is lower than past height!'

    return new_state


if __name__ == '__main__':
    UserList = []
    UserStateList = []
    TRList = []
    UState = dict()
    UserListP = []

    class User:
        def __init__(self, private_key, nonce):
            self.private_key = private_key
            self.nonce = nonce

    for i in range(10):
        newuser = User(ec.generate_private_key(
            ec.SECP256K1, default_backend()), 0)
        UserListP.append(newuser)
        UserList.append(calculate_sha1_hash(
            private_key_to_public_key(newuser.private_key)))
        UState[calculate_sha1_hash(private_key_to_public_key(
            newuser.private_key))] = UserState(100, 0)

    UState[bytes.fromhex('433a72a399823750c766bfa9f27b3948055fbb4b')
           ] = UserState(100, 0)

    def TR_Generator():
        TRList = []
        for i in range(5):
            randomlist = random.sample(range(0, 10), 2)
            amount = random.randint(2, 7)
            fee = random.randint(1, amount-1)
            if UState[UserList[randomlist[0]]].balance >= amount:
                t1 = create_signed_transaction(
                    UserListP[randomlist[0]].private_key, UserList[randomlist[1]], amount, fee, UserListP[randomlist[0]].nonce+1)
                UserListP[randomlist[0]].nonce += 1
                TRList.append(t1)
                print('Sender Hash:', t1.sender_hash.hex())
                print('Recipient Hash:', t1.recipient_hash.hex())
                print('Sender public key:', t1.sender_public_bytes)
                print('Amount:', t1.amount)
                print('Fee: ', t1.fee)
                print('Nonce: ', t1.nonce)
                print('Signature: ', t1.signature.hex())
                print('Txid: ', t1.txid.hex())
                print('========================')
        return TRList

    US = dict()
    BS = BlockchainState([], UState, 0)

    for i in range(20):
        if i == 0:
            previous = bytes.fromhex(
                '0000000000000000000000000000000000000000000000000000000000000000')
        else:
            previous = b.block_id
        height = i
        transactions = TR_Generator()
        timestamp = int(time())
        print("time1=", timestamp, '     No=', i)
        miner = bytes.fromhex('433a72a399823750c766bfa9f27b3948055fbb4b')
        difficulty = BS.calculate_difficulty()
        print('DEFF=', difficulty)
        b = mine_block(previous, height, miner,
                       transactions, timestamp, difficulty)
        BS.verify_and_apply_block(b)
        print("time2=", int(time()))
