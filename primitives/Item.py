# Copyright (c) 2021 JannesM
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


class Item:
    """Primitive class that describes a minecraft item
    """

    id = ""
    durability = 0.0
    amount = 0
    enchantments = []
    content = []

    def __init__(self, id, amount, durability=None, enchantments=None, content=None) -> None:
        self.id = id
        self.amount = amount
        self.durability = durability
        self.enchantments = enchantments
        self.content = content


