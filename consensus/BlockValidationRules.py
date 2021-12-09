# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from primitives.Block import Block

def chronologicalConsensus(block: Block, prevBlock: Block) -> bool:
    """Function that describes the chronological consensus of the blockchain

    Args:
        block (Block): current block
        prevBlock (Block): previous block

    Returns true if chronological consensus is comprehensible
    """

    if block.height == 0 and prevBlock is None:
        return True

    if (block.height == prevBlock.height + 1) and (block.timestamp > prevBlock.timestamp):
        return True
    else:
        return False

def chainConsensus(block: Block, prevBlock: Block) -> bool:
    """Function that describes the chain consensus of the blockchain

    Args:
        block (Block): current block
        prevBlock (Block): previous block

    Returns true if chain consensus is comprehensible
    """

    if block.prevHash == prevBlock.hash:
        return True
    else:
        return False

def blockConsensus(block: Block) -> bool:
    """Function that defines the consensus within a block

    Args:
        block (Block): any block

    Returns true if the blocks consensus is comprehensible
    """
    # validating completeness
    if block.height == 0:
        if not block.hash or not block.timestamp:
            print('[Validation] Genesis is missing some attributs!')
            return False    
    else:        
        if not block.hash or not block.prevHash or not block.timestamp:
            print('[Validation] Block is missing some attributs!')
            return False
    
    if len(block.transactions) == 0:
        print('[Validation] Block has no transactions!')
        return False

    # comparing hashes
    if block.hash != block.calculate_hash():
        print('[Validation] Block has wrong hash!')
        return False

    if block.merkle_root != block.calculate_merkle_root():
        print('[Validation] Block has wrong merkle root!')
        return False


    # verify proof of work
    difficulty = 3
    if not block.hash.hex()[:difficulty] != ''.join(str(0) for _ in range(difficulty)):
        print('[Validation] Blocks PoW failed!')
        return False

    return True

def blockReward(block: Block):
    """Factor to determ the reward of a block

    Args:
        block (Block): [description]

    Returns:
        [type]: [description]
    """

    initial_value = 50.0
    limit = 100000

    factor = (block.height / limit) + (1-((block.height % limit) / limit))
    return initial_value / factor
