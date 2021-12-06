# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from primitives.Block import Block

def genesis() -> Block:
    """Initial function that defines the genesis block

    Returns an empty block
    """

    return Block(0, "Peridot Genesis", [], [])

def chronologicalConsensus(block: Block, prevBlock: Block) -> bool:
    """Function that describes the chronological consensus of the blockchain

    Args:
        block (Block): current block
        prevBlock (Block): previous block

    Returns true if chronological consensus is comprehensible
    """

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

    # TODO: add consensus rules for stake and transactions
    
    # hash consensus
    if not block.hash:
        return False

    if block.hash != block.calculateHash():
        return False

    # stake consensus
    if len(block.stake) == 0 and block.height != 0:
        return False

    # transaction consensus
    if len(block.transactions) == 0 and block.height != 0:
        return False

    return True
