import hashlib
from typing import Dict, Set

class MerkleNode:
    # Node in the tree
    def __init__(self, hash_value: str, is_leaf: bool = False):
        self.hash = hash_value
        self.is_leaf = is_leaf
        self.left = None
        self.right = None

class MerkleTree:
    # Merkle tree implementation
    
    # hash_items : dictionary mapping item id's to their hash values
    def __init__(self, hashes: Set[str] = None):
        self.root = None
        if hashes:
            self.build_tree(hashes)

    # hash 2 child nodes to produce a parent    
    def _hash_pair(self, left: str, right: str) -> str:
        combined = left + right
        return hashlib.sha256(combined.encode()).hexdigest()
    
    # Build the tree from a dict of items
    # hash_items : dictionary mapping item id's to their hash values
    def build_tree(self, hashes: Set[str]) -> None:
        if not hashes:
            self.root = MerkleNode(hashlib.sha256(b'empty').hexdigest())
            return
        
        # Create leaf nodes
        leaves = []
        for hash_value in sorted(hashes):
            # Verify hash is 32 bytes (64 hex chars)
            #if len(hash_value) != 64:
            #    raise ValueError(f"Hash for item {item_id} is not 32 bytes")
            leaves.append(MerkleNode(hash_value, is_leaf=True))
        
        # Build the tree bottom-up
        nodes = leaves
        while len(nodes) > 1:
            next_level = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1] if i + 1 < len(nodes) else left
                parent_hash = self._hash_pair(left.hash, right.hash)
                parent = MerkleNode(parent_hash)
                parent.left = left
                parent.right = right
                next_level.append(parent)
            nodes = next_level
        
        self.root = nodes[0]
    
    def get_root_hash(self) -> str:
        # Root hash of the tree
        return self.root.hash if self.root else ""
    
    def serialize(self) -> Dict:
        # Serialize the tree for transmission
        def serialize_node(node):
            if not node:
                return None
            result = {"hash": node.hash}
            if node.is_leaf:
                result["leaf"] = True
            else:
                result["left"] = serialize_node(node.left)
                result["right"] = serialize_node(node.right)
            return result
        
        return serialize_node(self.root)
    
    @staticmethod
    def deserialize(data: Dict) -> 'MerkleTree':
        # Deserialize
        tree = MerkleTree()
        
        def deserialize_node(node_data):
            if not node_data:
                return None
                
            if node_data.get("leaf", False):
                node = MerkleNode(node_data["hash"], is_leaf=True)
            else:
                node = MerkleNode(node_data["hash"])
                node.left = deserialize_node(node_data.get("left"))
                node.right = deserialize_node(node_data.get("right"))
            return node
            
        tree.root = deserialize_node(data)
        return tree
    
    def find_differences(self, other_tree: 'MerkleTree') -> Set[str]:
        # Compare this tree with another and return the different leaf nodes id's
        different_hashes = set()
        
        def compare_nodes(node1, node2):
            if not node1 or not node2:
                return
                
            if node1.hash != node2.hash:
                if node1.is_leaf and node2.is_leaf:
                    different_hashes.add(node1.hash)
                else:
                    compare_nodes(node1.left, node2.left)
                    compare_nodes(node1.right, node2.right)
        
        compare_nodes(self.root, other_tree.root)
        return different_hashes
    