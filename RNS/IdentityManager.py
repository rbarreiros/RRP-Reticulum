import os
import threading
import RNS
import json
import asyncio
import time
import traceback

from RNS.vendor import umsgpack
from typing import Set, Dict
from .Merkle import MerkleTree

class RequestMessage(RNS.MessageBase):
    MSGTYPE = 0x0000

    def __init__(self, json = None):
        self.json = json
        self._channel = None  # Will store the channel reference

    def pack(self) -> bytes:
        return umsgpack.packb((json.dumps(self.json).encode()))
    
    def unpack(self, raw):
        self.json = json.loads(umsgpack.unpackb(raw))

class SyncMessage(RNS.MessageBase):
    MSGTYPE = 0x0001

    CMD_GET_ROOT    = "get_root_hash"
    CMD_GET_MERKLE  = "get_merkle_tree"
    CMD_GET_HASHES  = "get_hashes"
    CMD_GET_ALL     = "get_all"
    CMD_GET_DELETED = "get_deleted"

    def __init__(self, json = None) -> None:
        self.json = json
        self._channel = None
    
    def pack(self) -> bytes:
        return umsgpack.packb((json.dumps(self.json).encode()))

    def unpack(self, raw: bytes) -> None:
        self.json = json.loads(umsgpack.unpackb(raw))

class IdentityManagerException(Exception):
    pass

class IdentityManager:
    # Poll sync request interval
    # Should be bigger than SYNC_MAX_RETRIES * SYNC_RETRY_INTERVAL
    SYNC_POLL_INTERVAL = 300

    # Sync retry interval, on failure, will wait X seconds to retry
    SYNC_RETRY_INTERVAL = 60

    # max retries before give up
    SYNC_MAX_RETRIES = 3

    # Init, with config 
    def __init__(self, config):
        # The identities that are authorized 
        self.authorized_identities = set()

        self.config = config

        # Configuration options
        self.SYNC_POLL_INTERVAL = config.get('sync_interval', 300)
        self.SYNC_RETRY_INTERVAL = config.get('retry_interval', 60)
        self.SYNC_MAX_RETRIES = config.get('max_retries', 3)

        # TODO
        # Maybe, create a system that allows for a previous registration
        # then, master registration server returns a token, that can be
        # used in config to register on master server, this node then would
        # generate its identity, send it to register, master server on 
        # success would save this identity, mark as registered and invalidate
        # token, or use it for later if its required to re-register, but, 
        # invalidating previous identity.
        self.sync_server_hash = config.get('master_server_hash')
        if not self.sync_server_hash:
            raise IdentityManagerException("No sync server hash configured.")

        if len(self.sync_server_hash) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH // 8) * 2):
            raise IdentityManagerException("Sync server hash length is invalid.")

        if isinstance(self.sync_server_hash, str):
            self.sync_server_hash = bytes.fromhex(self.sync_server_hash)

        # Start reticulum sync server Link
        self.server_destination = None
        self.server_link = None
        self.server_channel = None
        self._initialize_reticulum_client()

        # Should probably enforce our own hash right ? right ??
        #RNS.log(f"Our own hash: {RNS.Transport.identity.hash.hex()}", RNS.LOG_DEBUG)
        #
        # debug identities
        #self.authorized_identities.add(RNS.Transport.identity.hash)

        # Cache paths
        self.cache_dir = os.path.join(RNS.Reticulum.cachepath, 'idmanager')
        self.cache_file = os.path.join(self.cache_dir, 'idmanager.json')
        self.merkle_cache_file = os.path.join(self.cache_dir, 'merkle.json')

        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)

        self._load_cache()

        # Make sure we're in
        if RNS.Transport.identity.hash not in self.authorized_identities:
            self.authorized_identities.add(RNS.Transport.identity.hash.hex())

        # Obviously, add the sync server to the list of authorized identities
        # we have the server destination hash, not identity, get his identity!!!
        # TODO for now hardcoded, for testing
        #self.authorized_identities.add('fa9d530bf774a9ab7fbe2590358f9b87')

        # Remove, test
        #self.authorized_identities.add('df160eed0bdecba906b2040ac82226c2')
        #self.authorized_identities.add('72afa1832f38efa345aa34be70db46ef')

        # Threading stuff
        self._stop_event = threading.Event()
        self._sync_thread = None
        self._sync_lock = threading.Lock()
        
        # Merkle tree for local identities
        self.merkle_tree = None
        self._update_merkle_tree()

        RNS.log(f"Identity Manager loaded {len(self.authorized_identities)} identities.", RNS.LOG_INFO)
        
    def _update_merkle_tree(self):
        """Update the local merkle tree with current identities"""
        self.merkle_tree = MerkleTree(self.authorized_identities)
        RNS.log(f"Local Merkle tree updated with {len(self.authorized_identities)} identities", RNS.LOG_DEBUG)
        RNS.log(f"Local Merkle root hash: {self.merkle_tree.get_root_hash()}", RNS.LOG_DEBUG)

    def start(self) -> None:
        # Start the identity sync thread
        if self._stop_event.is_set():
            RNS.log("Already running", RNS.LOG_DEBUG)
            return 
        
        self._stop_event.clear()

        # Create event loop in new thread
        def run_sync_loop():
            try:
                while not self._stop_event.is_set():
                    try:
                        # Check link status
                        if not self.server_link or self.server_link.status != RNS.Link.ACTIVE:
                            self._sync_establish_link()
                            time.sleep(self.SYNC_RETRY_INTERVAL)
                            continue

                        # Perform sync with server
                        success = self._sync_with_server()
                        if success:
                            RNS.log("Sync completed successfully", RNS.LOG_DEBUG)
                            time.sleep(self.SYNC_POLL_INTERVAL)
                        else:
                            RNS.log("Sync failed, will retry", RNS.LOG_WARNING)
                            time.sleep(self.SYNC_RETRY_INTERVAL)
                    except Exception as e:
                        RNS.log(f"Error in sync loop: {str(e)}", RNS.LOG_ERROR)
                        time.sleep(self.SYNC_RETRY_INTERVAL)
            except Exception as e:
                RNS.log(f"Fatal error in sync thread: {str(e)}", RNS.LOG_ERROR)
        
        self._sync_thread = threading.Thread(target=run_sync_loop)
        self._sync_thread.daemon = True

        RNS.log("Starting identity sync thread.", RNS.LOG_DEBUG)
        self._sync_thread.start()

    def stop(self):
        # Stop the identity sync thread
        self._stop_event.set()
        if self._sync_thread:
            self._sync_thread.join()
            RNS.log("Identity Manager sync thread stopped", RNS.LOG_INFO)

    def is_authorized(self, packet: bytes) -> bool:
        from pprint import pprint

        # Check if the packet comes from the identity server, if it does, apply no
        # filtering whatsoever!!!!!!

        if packet.packet_type == RNS.Packet.DATA:
            #RNS.log(f"DATA ----- TODO", RNS.LOG_DEBUG)
            #identity = RNS.Identity(create_keys=False)
            #identity.load_public_key(packet.data[:RNS.Identity.KEYSIZE//8])
            #RNS.log(f"DATA ---- Source ID Hash is {identity.hash.hex()}", RNS.LOG_DEBUG)
            #RNS.log(f"DATA ---- destination_hash is {packet.destination_hash.hex()}", RNS.LOG_DEBUG)

            # is this a link ?
            if packet.destination_type == RNS.Destination.LINK:
                for link in RNS.Transport.active_links:
                    if link.link_id == packet.destination_hash:
                        RNS.log(f"DATA ---- LINK PACKET", RNS.LOG_DEBUG)
                        # TODO
                        return True
            else:
                # get destination 
                #for destination in Transport.destinations:
                    #if destination.hash == packet.destination_hash and destination.type == packet.destination_type:
                if packet.destination_type == RNS.Destination.PLAIN: # packet is just local broadcast
                    # should we ignore ?!?!?!
                    RNS.log("PLAIN packet, IGNORE fow now!", RNS.LOG_DEBUG)
                    return True
                else:

                    RNS.log(f"""
                        DATA ---- 
                        DESTINATION {packet.destination_hash.hex()} need to find destination identity 
                        Destination Type: {packet.destination_type}
                        Context is: {packet.context} 
                        Header type is {packet.header_type}
                        """, RNS.LOG_DEBUG)

                    # Here we check the destination identity                    
                    try:                            
                        identity = RNS.Identity.recall(packet.destination_hash)
                        RNS.log(f"DATA ---- Packet Destination identity hash is : {identity.hash.hex()}", RNS.LOG_DEBUG)
                    except Exception:
                        pass

                    return identity.hash.hex() in self.authorized_identities

        elif packet.packet_type == RNS.Packet.ANNOUNCE:
            # Announce has source identity in it
            if hasattr(packet, 'destination_hash') and packet.destination_hash:
                identity = RNS.Identity.recall(packet.destination_hash)
                if not identity:
                    RNS.log("ANNOUNCE ---- First Announce packet received. Extracking...")
                    identity = RNS.Identity(create_keys=False)
                    identity.load_public_key(packet.data[:RNS.Identity.KEYSIZE//8])
                    RNS.log(f"ANNOUNCE ---- Source ID Hash is {identity.hash.hex()} ---- key {packet.data[:RNS.Identity.KEYSIZE//8]}", RNS.LOG_DEBUG)
                else:
                    RNS.log(f"ANNOUNCE ---- Source ID Hash is {identity.hash.hex()} ---- key {packet.destination_hash}", RNS.LOG_DEBUG)

                return identity.hash.hex() in self.authorized_identities
            else:
                RNS.log(f"ANNOUNCE ---- Unknown packet source, discarding....")
                return False
        elif packet.packet_type == RNS.Packet.LINKREQUEST:
            RNS.log(f"LINKREQUEST ---- TODO")
            return True
        elif packet.packet_type == RNS.Packet.PROOF:
            RNS.log(f"PROOF ---- TODO")
            # Proofs are result of DATA packets, if they don't go through, there'll be no proof, should we check anyway ?
            return True
        else:
            RNS.log(f"UNKNOWN PACKET TYPE ---- DISCARDING")
            # unknown, is rejected

        return False

    #### Privates

    # Sync Server

    def _initialize_reticulum_client(self) -> None:
        try:
            # Verify if our transport was already initialized and has an identity!!!
            # should we fix this ourselves, or ?!?!?!
            if not RNS.Transport.identity:
                raise IdentityManagerException("Transport hasn't initialized yet, node has no identity yet.... restart the node.")

            self._sync_establish_link()

        except Exception as e:
            RNS.log(f"Error initializing reticulum. Error {traceback.print_exc()}", RNS.LOG_DEBUG)

    def _sync_establish_link(self) -> None:
        try:
            server = RNS.Identity.recall(self.sync_server_hash)

            if not server:
                RNS.Transport.request_path(self.sync_server_hash)
                server = RNS.Identity.recall(self.sync_server_hash)

                if not server:
                    return

            self.server_destination = RNS.Destination(
                server,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                "idserver",
                "sync"
            )

            self.server_link = RNS.Link(self.server_destination)
            self.server_link.set_link_established_callback(self._sync_server_link_established)
            self.server_link.set_link_closed_callback(self._sync_server_link_closed)
        except Exception as e:
            RNS.log(f"Unable to create link connection to sync server {e}", RNS.LOG_DEBUG)

    def _sync_server_link_established(self, link) -> None:
        self.server_channel = self.server_link.get_channel()
        self.server_channel.register_message_type(RequestMessage)
        #self.server_channel.register_message_type(ReplyMessage)
        self.server_channel.add_message_handler(self._sync_channel_msg_received)
        self.server_link.identify(RNS.Transport.identity)
        RNS.log(f"Link established with sync server")
        
        # Send ping request to check sync status right away
        self._send_ping_request()

    def _sync_server_link_closed(self, link) -> None:
        # Link is down, check why, warn the user, try to reconnect again on each sync attempt
        if self.server_link.teardown_reason == RNS.Link.TIMEOUT:
            RNS.log("Link to sync server disconnected, timed out...", RNS.LOG_DEBUG)
        elif self.server_link.teardown_reason == RNS.Link.DESTINATION_CLOSED:
            RNS.log("Link disconnected by sync server.", RNS.LOG_DEBUG)
        else:
            RNS.log("Link to sync server closed by an unknown reason.", RNS.LOG_DEBUG)

    def _sync_channel_msg_received(self, message) -> bool:
        try:
            # Handle server pings and other server-initiated messages
            if isinstance(message, RequestMessage):
                action = message.json.get('action')
                
                if action == 'server_ping':
                    # Server is pinging us, respond with our merkle root
                    server_merkle_hash = message.json.get('merkle_hash')
                    our_merkle_hash = self.merkle_tree.get_root_hash()
                    needs_sync = server_merkle_hash != our_merkle_hash
                    
                    response = {
                        'action': 'pong',
                        'merkle_hash': our_merkle_hash,
                        'needs_sync': needs_sync
                    }
                    
                    reply = RequestMessage(json=response)
                    self.server_channel.send(reply)
                    
                    # If we need to sync, request a sync
                    if needs_sync:
                        RNS.log(f"Server ping detected merkle mismatch, initiating sync", RNS.LOG_DEBUG)
                        self._request_sync()
                    
                    return True
            
            return False
        except Exception as e:
            RNS.log(f"Error handling server message: {str(e)}", RNS.LOG_ERROR)
            return False

    def _send_ping_request(self) -> None:
        """Send ping to server to check sync status"""
        if not self.server_channel:
            RNS.log("Cannot send ping: server channel not established", RNS.LOG_WARNING)
            return
        
        try:
            message = RequestMessage(json={
                'action': 'ping',
                'merkle_hash': self.merkle_tree.get_root_hash()
            })
            self.server_channel.send(message)
            RNS.log("Sent ping request to sync server", RNS.LOG_DEBUG)
        except Exception as e:
            RNS.log(f"Error sending ping request: {str(e)}", RNS.LOG_ERROR)

    def _request_sync(self) -> None:
        """Send sync request to server with our merkle tree"""
        if not self.server_channel:
            RNS.log("Cannot request sync: server channel not established", RNS.LOG_WARNING)
            return
        
        try:
            message = RequestMessage(json={
                'action': 'sync_request',
                'merkle_tree': self.merkle_tree.serialize()
            })
            self.server_channel.send(message)
            RNS.log("Sent sync request to server", RNS.LOG_DEBUG)
        except Exception as e:
            RNS.log(f"Error sending sync request: {str(e)}", RNS.LOG_ERROR)

    def _request_diffs(self, hashes_to_request) -> None:
        """Request specific identity hashes from server"""
        if not self.server_channel:
            RNS.log("Cannot request diffs: server channel not established", RNS.LOG_WARNING)
            return
        
        try:
            message = RequestMessage(json={
                'action': 'diff_request',
                'requested_hashes': list(hashes_to_request)
            })
            self.server_channel.send(message)
            RNS.log(f"Requested {len(hashes_to_request)} specific identities from server", RNS.LOG_DEBUG)
        except Exception as e:
            RNS.log(f"Error requesting diffs: {str(e)}", RNS.LOG_ERROR)

    def _request_full_sync(self) -> None:
        """Request full identity dataset from server"""
        if not self.server_channel:
            RNS.log("Cannot request full sync: server channel not established", RNS.LOG_WARNING)
            return
        
        try:
            message = RequestMessage(json={
                'action': 'full_sync_request'
            })
            self.server_channel.send(message)
            RNS.log("Requested full identity dataset from server", RNS.LOG_DEBUG)
        except Exception as e:
            RNS.log(f"Error requesting full sync: {str(e)}", RNS.LOG_ERROR)

    #### Cache

    # load cached hashes
    def _load_cache(self) -> None:
        try:
            with open(self.cache_file, 'r') as f:
                self.authorized_identities = set(json.load(f))
        except FileNotFoundError:
            RNS.log(f"Database {self.cache_file} not found. Creating a new empty database.", RNS.LOG_DEBUG)
        except json.JSONDecodeError:
            RNS.log(f"Error decoding database file {self.cache_file}. Starting with empty database.", RNS.LOG_DEBUG)

    # save hashes to cache
    def _save_cache(self) -> None:
        with open(self.cache_file, 'w') as f:
            json.dump(list(self.authorized_identities), f)
        RNS.log(f"Saved {len(self.authorized_identities)} identities to the local cache", RNS.LOG_DEBUG)
        
        # Update merkle tree after changes
        self._update_merkle_tree()

    def _check_suitable_interfaces(self) -> bool:
        # In a real implementation, you might want to check for appropriate network interfaces
        # For now, we'll assume all interfaces are suitable
        return True

    # sync with server
    def _sync_with_server(self) -> bool:
        """Perform sync with server, returns True if successful"""
        try:
            with self._sync_lock:
                # First, send ping to check if we need to sync
                self._send_ping_request()
                
                # Give server time to process
                time.sleep(1)
                
                # Check if server link is still active
                if not self.server_link or self.server_link.status != RNS.Link.ACTIVE:
                    return False
                
                # Request full sync for now (in a real implementation, you'd use incremental syncs)
                # We could implement message response tracking for more robust sync management
                self._request_full_sync()
                
                # For now, we'll consider this successful (actual success will be determined
                # when we receive and process the response in _sync_channel_msg_received)
                return True
                
        except Exception as e:
            RNS.log(f"Error syncing with server: {str(e)}", RNS.LOG_ERROR)
            return False

    def _get_all_hashes(self) -> Set[str]:
        """Get all identity hashes from local cache"""
        return self.authorized_identities.copy()

    def _update_hashes(self, new_hashes: Set[str]) -> None:
        """Add new identity hashes to authorized set"""
        if not new_hashes:
            return
            
        self.authorized_identities.update(new_hashes)
        self._save_cache()
        RNS.log(f"Added {len(new_hashes)} new identities", RNS.LOG_INFO)

    def _remove_hashes(self, removed_hashes: Set[str]) -> None:
        """Remove identity hashes from authorized set"""
        if not removed_hashes:
            return
            
        self.authorized_identities.difference_update(removed_hashes)
        self._save_cache()
        RNS.log(f"Removed {len(removed_hashes)} identities", RNS.LOG_INFO)
