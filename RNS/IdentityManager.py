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

    # Connection status constants
    STATUS_DISCONNECTED = 0
    STATUS_CONNECTING = 1
    STATUS_CONNECTED = 2
    STATUS_SYNCING = 3

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
            raise IdentityManagerException("IMANAGER : No sync server hash configured.")

        if len(self.sync_server_hash) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH // 8) * 2):
            raise IdentityManagerException("IMANAGER : Sync server hash length is invalid.")

        if isinstance(self.sync_server_hash, str):
            self.sync_server_hash = bytes.fromhex(self.sync_server_hash)

        # Master server identity, we could try and figure out a way of getting
        # master server identity through a registration method, before we enable any
        # kind of packet filtering, for now, we read it from the config
        self.sync_server_identity = config.get('master_server_identity')
        if not self.sync_server_identity:
            raise IdentityManagerException("IMANAGER : No sync server identity configured.")

        if len(self.sync_server_identity) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH // 8) * 2):
            raise IdentityManagerException("IMANAGER : Sync server identity length is invalid.")

        # Start reticulum 
        self.server_destination = None
        self.server_link = None
        self.server_channel = None
        self.server_link_status = RNS.Link.CLOSED

        self.server_identity_confirmed = False

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

        # Make sure we're in, this will later be ovewritten by the database
        if RNS.Transport.identity.hash not in self.authorized_identities:
            self.authorized_identities.add(RNS.Transport.identity.hash.hex())

        # sync server identity, this will later be ovewritten by the database
        if self.sync_server_identity not in self.authorized_identities:
            self.authorized_identities.add(self.sync_server_identity)

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

        # Sync tracking
        self.last_sync_time = 0
        self.sync_in_progress = False

        # Start link
        self._sync_establish_link()
        RNS.log(f"IMANAGER : Identity Manager loaded {len(self.authorized_identities)} identities.", RNS.LOG_INFO)
        
    def _update_merkle_tree(self):
        """Update the local merkle tree with current identities"""
        self.merkle_tree = MerkleTree(self.authorized_identities)
        RNS.log(f"IMANAGER : Local Merkle tree updated with {len(self.authorized_identities)} identities", RNS.LOG_DEBUG)
        RNS.log(f"IMANAGER : Local Merkle root hash: {self.merkle_tree.get_root_hash()}", RNS.LOG_DEBUG)

    def start(self) -> None:
        # Start the identity sync thread
        if self._stop_event.is_set():
            RNS.log("IMANAGER : Already running", RNS.LOG_DEBUG)
            return 
        
        self._stop_event.clear()

        # Create event loop in new thread
        def run_sync_loop():
            try:
                while not self._stop_event.is_set():
                    if self.server_link_status == RNS.Link.CLOSED:
                        self._sync_establish_link()
                        
                    # Sleep for a bit before checking again
                    time.sleep(5)
            except Exception as e:
                RNS.log(f"IMANAGER : Fatal error in sync thread: {str(e)}", RNS.LOG_ERROR)
        
        self._sync_thread = threading.Thread(target=run_sync_loop)
        self._sync_thread.daemon = True

        RNS.log("IMANAGER : Starting identity sync thread.", RNS.LOG_DEBUG)
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
                        #RNS.log(f"DATA ---- LINK PACKET TODO", RNS.LOG_DEBUG)
                        RNS.log(f"DATA ---- Active Link - Validating Identity {link.destination.identity.hash.hex()} ", RNS.LOG_DEBUG)
                        return link.destination.identity.hash.hex() in self.authorized_identities
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
                        RNS.log(f"DATA ---- Validating Packet Destination identity : {identity.hash.hex()}", RNS.LOG_DEBUG)
                    except Exception:
                        pass

                    return identity.hash.hex() in self.authorized_identities

        elif packet.packet_type == RNS.Packet.ANNOUNCE:
            # Announce has source identity in it
            if hasattr(packet, 'destination_hash') and packet.destination_hash:
                identity = RNS.Identity.recall(packet.destination_hash)
                if not identity:
                    #RNS.log("ANNOUNCE ---- First Announce packet received. Extracking...")
                    identity = RNS.Identity(create_keys=False)
                    identity.load_public_key(packet.data[:RNS.Identity.KEYSIZE//8])
                    RNS.log(f"ANNOUNCE ---- Validating identity {identity.hash.hex()}", RNS.LOG_DEBUG)
                else:
                    RNS.log(f"ANNOUNCE ---- Validating identity {identity.hash.hex()}", RNS.LOG_DEBUG)

                return identity.hash.hex() in self.authorized_identities
            else:
                RNS.log(f"ANNOUNCE ---- Unknown packet source, discarding....")
                return False
        elif packet.packet_type == RNS.Packet.LINKREQUEST:
            RNS.log(f"LINKREQUEST ---- WORK IN PROGRESS")

            if RNS.Link.link_id_from_lr_packet(packet) in RNS.Transport.link_table:
                destination_hash = RNS.Transport.link_table[RNS.Link.link_id_from_lr_packet(packet)][6]
                RNS.log(f"LINKREQUEST ---- FROM TABLE: {destination_hash.hex()}", RNS.LOG_DEBUG)

            try:                            
                identity = RNS.Identity.recall(packet.destination_hash)
                if not identity:
                    RNS.log("LINKREQUEST ---- First Announce packet received. Extracking...")
                    identity = RNS.Identity(create_keys=False)
                    identity.load_public_key(packet.data[:RNS.Identity.KEYSIZE//8])
                    RNS.log(f"LINKREQUEST ---- Source ID Hash is {identity.hash.hex()} ---- key {packet.data[:RNS.Identity.KEYSIZE//8].hex()}", RNS.LOG_DEBUG)
                else:
                    RNS.log(f"LINKREQUEST ---- Source ID Hash is {identity.hash.hex()} ---- key {packet.destination_hash.hex()}", RNS.LOG_DEBUG)
            except Exception:
                    pass
            
            return True
        elif packet.packet_type == RNS.Packet.PROOF:
            #RNS.log(f"PROOF ---- ")

            ### Proof of a link request
            for link in RNS.Transport.pending_links:
                if link.link_id == packet.destination_hash:
                    RNS.log(f"PROOF ---- Pending Link - Validating Identity {link.destination.identity.hash.hex()} ", RNS.LOG_DEBUG)
                    return link.destination.identity.hash.hex() in self.authorized_identities

            for link in RNS.Transport.active_links:
                if link.link_id == packet.destination_hash:
                    RNS.log(f"PROOF ---- Active Link - Validating Identity {link.destination.identity.hash.hex()} ", RNS.LOG_DEBUG)
                    return link.destination.identity.hash.hex() in self.authorized_identities

            # Do we need any more checks !?!?!?
            RNS.log(f"PROOF ---- Destination type: {packet.destination_type}", RNS.LOG_DEBUG)
            RNS.log(f"PROOF ---- Context: {packet.context}", RNS.LOG_DEBUG)
            # transport ?
            if packet.destination_hash in RNS.Transport.link_table:
                RNS.log(f"PROOF ---- Packet destination hash is in RNS.Transport.link_table", RNS.LOG_DEBUG)

                link_entry = RNS.Transport.link_table[packet.destination_hash]
                peer_identity = RNS.Identity.recall(link_entry[RNS.Transport.IDX_LT_DSTHASH])
                if peer_identity:
                    RNS.log(f"PROOF ---- Identity Hash is {peer_identity.hash.hex()}", RNS.LOG_DEBUG)

            return True
        else:
            RNS.log(f"UNKNOWN PACKET TYPE ---- DISCARDING")
            # unknown, is rejected

        return False

    #### Privates

    ###
    ### Attempts to start a link with master server
    ###
    def _sync_establish_link(self) -> None:
        try:
            # Verify if our transport was already initialized and has an identity!!!
            # should we fix this ourselves, or ?!?!?!
            if not RNS.Transport.identity:
                raise IdentityManagerException("IMANAGER : Transport hasn't initialized yet, node has no identity yet.... restart the node.")

            if self.server_link_status == RNS.Link.ACTIVE or self.server_link_status == RNS.Link.PENDING:
                RNS.log("IMANAGER : Link already established or pending", RNS.LOG_DEBUG)
                return
            
            RNS.log("IMANAGER : Attempting to establish link to sync server", RNS.LOG_DEBUG)

            server = RNS.Identity.recall(self.sync_server_hash)

            if not server:
                RNS.Transport.request_path(self.sync_server_hash)
                server = RNS.Identity.recall(self.sync_server_hash)

                if not server:
                    RNS.log("IMANAGER : Could not recall server identity, will retry later", RNS.LOG_DEBUG)
                    return

            self.server_destination = RNS.Destination(
                server,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                "idserver",
                "sync"
            )

            self.server_link_start = RNS.Link(self.server_destination)
            self.server_link_start.set_link_established_callback(self._sync_server_link_established)
            self.server_link_start.set_link_closed_callback(self._sync_server_link_closed)

            self.server_link_status = RNS.Link.PENDING
        except Exception as e:
            RNS.log(f"IMANAGER : Unable to create link connection to sync server {e}", RNS.LOG_DEBUG)
            self.connection_status = self.STATUS_DISCONNECTED

    ###
    ### A link with the server was established
    ###
    def _sync_server_link_established(self, link) -> None:
        """Callback when link to sync server is established"""
        try:
            RNS.log("IMANAGER : Link established with sync server", RNS.LOG_INFO)
        
            # Set up callback for when the server identifies back
            #link.set_remote_identified_callback(self._server_identity_confirmed)

            # Identify ourselves
            link.identify(RNS.Transport.identity)
        
            self.server_channel = link.get_channel()
            self.server_channel.register_message_type(RequestMessage)
            self.server_channel.add_message_handler(self._sync_channel_msg_received)
            self.server_link_status = RNS.Link.ACTIVE

        except Exception as e:
            RNS.log(f"IMANAGER : Error in link established handler: {str(e)}", RNS.LOG_ERROR)
            self.server_link_status =  RNS.Link.CLOSED

    def _sync_server_link_closed(self, link) -> None:
        """Callback when link to sync server is closed"""
        try:
            # Link is down, check why, warn the user
            if hasattr(link, 'teardown_reason'):
                if link.teardown_reason == RNS.Link.TIMEOUT:
                    RNS.log("IMANAGER : Link to sync server disconnected, timed out...", RNS.LOG_DEBUG)
                elif link.teardown_reason == RNS.Link.DESTINATION_CLOSED:
                    RNS.log("IMANAGER : Link disconnected by sync server.", RNS.LOG_DEBUG)
                else:
                    RNS.log(f"IMANAGER : Link to sync server closed, reason: {link.teardown_reason}", RNS.LOG_DEBUG)

                self.server_link_status = RNS.Link.CLOSED
            else:
                RNS.log("IMANAGER : Link to sync server closed by an unknown reason.", RNS.LOG_DEBUG)
           
        except Exception as e:
            RNS.log(f"IMANAGER : Error in link closed handler: {str(e)}", RNS.LOG_ERROR)
            self.connection_status = self.STATUS_DISCONNECTED

    #def _server_identity_confirmed(self, link, identity):
    #    """Called when server confirms its identity"""
    #    try:
    #        RNS.log(f"IMANAGER : Server identity confirmed: {RNS.prettyhexrep(identity.hash)}", RNS.LOG_INFO)
            
            # Check if the identity matches what we expect
    #        if identity.hash.hex() != self.sync_server_identity:
    #            RNS.log(f"IMANAGER : Warning: Server identity {identity.hash.hex()} doesn't match expected {self.sync_server_identity}", RNS.LOG_WARNING)
                # we probably stop close the link then.....

    #        self.server_link_status = RNS.Link.ACTIVE

            # Send initial ping to check sync status
    #        self._send_ping_request()
            
    #    except Exception as e:
    #        RNS.log(f"IMANAGER : Error in server identity confirmed: {str(e)}", RNS.LOG_ERROR)

    def _sync_channel_msg_received(self, message) -> bool:
        """Handle incoming messages from server"""
        try:
            if not isinstance(message, RequestMessage) or not hasattr(message, 'json'):
                return False
                
            RNS.log(f"IMANAGER : Received message from server: {message.json.get('action', 'unknown')}", RNS.LOG_DEBUG)
            RNS.log(f"IMANAGER : JSON : {message.json}", RNS.LOG_DEBUG)

            if message.json.get('error', '') != '':
                # We got an error... Should do something about it
                RNS.log(f"Error: {message.json.get('error')} .... ", RNS.LOG_DEBUG)
                return True

            action = message.json.get('action')
            
            # Handle server-initiated ping
            if action == 'server_ping':
                self._handle_server_ping(message)
                return True
                
            # Handle sync responses
            elif action == 'pong':
                self._handle_pong_response(message)
                return True
                
            elif action == 'sync_response':
                self._handle_sync_response(message)
                return True
                
            elif action == 'diff_response':
                self._handle_diff_response(message)
                return True
                
            elif action == 'full_sync_response':
                self._handle_full_sync_response(message)
                return True
                
            return False
            
        except Exception as e:
            RNS.log(f"Error handling server message: {str(e)}", RNS.LOG_ERROR)
            return False





    def _handle_server_ping(self, message):
        """Handle server ping request"""
        try:
            server_merkle_hash = message.json.get('merkle_hash', '')
            our_merkle_hash = self.merkle_tree.get_root_hash()
            needs_sync = server_merkle_hash != our_merkle_hash
            
            # Respond with our current status
            response = {
                'action': 'pong',
                'merkle_hash': our_merkle_hash,
                'needs_sync': needs_sync
            }
            
            reply = RequestMessage(json=response)
            self.server_channel.send(reply)
            
            # If we need to sync, request it
            if needs_sync and not self.sync_in_progress:
                RNS.log("IMANAGER : Server ping detected merkle mismatch, requesting sync", RNS.LOG_INFO)
                self._request_sync()
                
        except Exception as e:
            RNS.log(f"IMANAGER : Error handling server ping: {str(e)}", RNS.LOG_ERROR)






    def _handle_pong_response(self, message):
        """Handle pong response from server after our ping"""
        try:
            server_merkle_hash = message.json.get('merkle_hash', '')
            needs_sync = message.json.get('needs_sync', False)
            
            if needs_sync and not self.sync_in_progress:
                RNS.log("Server indicates we need to sync, requesting sync", RNS.LOG_INFO)
                self._request_sync()
            else:
                RNS.log("Server indicates we're in sync", RNS.LOG_DEBUG)
                # Update last sync time even if we didn't need to sync
                self.last_sync_time = time.time()
                
        except Exception as e:
            RNS.log(f"Error handling pong response: {str(e)}", RNS.LOG_ERROR)


    ###
    ### Handles server sync response to our sync request
    ###
    def _handle_sync_response(self, message):
        """Handle sync response with difference hashes"""
        try:
            RNS.log(f"IMANAGER : Received sync response from server {message.json}", RNS.LOG_DEBUG)

            diff_hashes = set(message.json.get('diff_hashes', []))
            
            if diff_hashes:
                RNS.log(f"IMANAGER : Server identified {len(diff_hashes)} different hashes, requesting them", RNS.LOG_INFO)
                self._request_diffs(diff_hashes)
            else:
                RNS.log("IMANAGER : No differences found in merkle tree comparison but we requested a sync.... probably corrupted.", RNS.LOG_DEBUG)
                # We're already in sync
                self.sync_in_progress = False
                #self.last_sync_time = time.time()
                self._request_full_sync()
                
        except Exception as e:
            RNS.log(f"IMANAGER : Error handling sync response: {str(e)}", RNS.LOG_ERROR)
            self.sync_in_progress = False

    ###
    ### Handles server diff response to our diff request
    ###
    def _handle_diff_response(self, message):
        """Handle response with specific identity hashes"""
        try:
            new_identities = set(message.json.get('identities', []))
            
            if new_identities:
                RNS.log(f"IMANAGER : Received {len(new_identities)} identities from server", RNS.LOG_INFO)
                self._update_hashes(new_identities)
                
            # Sync is complete
            self.sync_in_progress = False
            self.last_sync_time = time.time()
            
        except Exception as e:
            RNS.log(f"IMANAGER : Error handling diff response: {str(e)}", RNS.LOG_ERROR)
            self.sync_in_progress = False

    ###
    ### Handle a full sync response from a full sync request
    ###
    def _handle_full_sync_response(self, message):
        """Handle full sync response with all identities"""
        try:
            server_identities = set(message.json.get('identities', []))
            server_merkle_hash = message.json.get('merkle_hash', '')
            
            if server_identities:
                RNS.log(f"IMANAGER : Received full identity set with {len(server_identities)} identities", RNS.LOG_INFO)
                
                # Calculate the differences
                current_identities = self.authorized_identities.copy()
                to_add = server_identities - current_identities
                to_remove = current_identities - server_identities
                
                # Make sure we don't remove ourselves or the server
                our_id = RNS.Transport.identity.hash.hex()
                if our_id in to_remove:
                    to_remove.remove(our_id)
                    
                if self.sync_server_identity in to_remove:
                    to_remove.remove(self.sync_server_identity)
                
                # Update our identity set
                if to_add:
                    RNS.log(f"IMANAGER : Adding {len(to_add)} new identities", RNS.LOG_INFO)
                    self._update_hashes(to_add)
                    
                if to_remove:
                    RNS.log(f"IMANAGER : Removing {len(to_remove)} obsolete identities", RNS.LOG_INFO)
                    self._remove_hashes(to_remove)
                
                if not to_add and not to_remove:
                    RNS.log("IMANAGER : No changes needed, already in sync", RNS.LOG_DEBUG)
            else:
                RNS.log("IMANAGER : Received empty identity set from server", RNS.LOG_WARNING)
                
            # Sync is complete
            self.sync_in_progress = False
            self.last_sync_time = time.time()
            
        except Exception as e:
            RNS.log(f"IMANAGER : Error handling full sync response: {str(e)}", RNS.LOG_ERROR)
            self.sync_in_progress = False

    # Sync Requests

    def _send_ping_request(self) -> None:
        """Send ping to server to check sync status"""
        if not self.server_channel or self.connection_status != self.STATUS_CONNECTED:
            RNS.log("Cannot send ping: not fully connected", RNS.LOG_WARNING)
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
            self._check_connection()  # Check and possibly reset connection


    ###
    ### Requests sync from server
    ###
    def _request_sync(self) -> None:
        """Send sync request to server with our merkle tree for incremental sync"""
        if not self.server_channel or self.server_link_status != RNS.Link.ACTIVE:
            RNS.log(f"IMANAGER : Cannot request sync: not fully connected {self.server_link_status}", RNS.LOG_WARNING)
            return
        
        if self.sync_in_progress:
            RNS.log("IMANAGER : Sync already in progress, skipping request", RNS.LOG_DEBUG)
            return
            
        try:
            # Set sync status
            self.sync_in_progress = True
            
            message = RequestMessage(json={
                'action': 'sync_request',
                'merkle_tree': self.merkle_tree.serialize()
            })

            self.server_channel.send(message)
            RNS.log("IMANAGER : Sent incremental sync request to server", RNS.LOG_INFO)
            
            # Set a timeout for sync completion
            threading.Timer(30.0, self._check_sync_timeout).start()
            
        except Exception as e:
            RNS.log(f"IMANAGER : Error sending sync request: {str(e)}", RNS.LOG_ERROR)
            self.sync_in_progress = False

    ###
    ### Requests the server for diffs 
    ###
    def _request_diffs(self, hashes_to_request) -> None:
        """Request specific identity hashes from server"""
        if not self.server_channel or self.server_link_status != RNS.Link.ACTIVE:
            RNS.log("IMANAGER : Cannot request diffs: not fully connected", RNS.LOG_WARNING)
            self.sync_in_progress = False
            return
        
        try:
            message = RequestMessage(json={
                'action': 'diff_request',
                'requested_hashes': list(hashes_to_request)
            })

            self.server_channel.send(message)
            RNS.log(f"IMANAGER : Requested {len(hashes_to_request)} specific identities from server", RNS.LOG_INFO)
        except Exception as e:
            RNS.log(f"IMANAGER : Error requesting diffs: {str(e)}", RNS.LOG_ERROR)
            self.sync_in_progress = False

    ###
    ### Requests a full sync
    ###
    def _request_full_sync(self) -> None:
        """Request full identity dataset from server"""
        if not self.server_channel or self.server_link_status != RNS.Link.ACTIVE:
            RNS.log("IMANAGER : Cannot request full sync: not fully connected", RNS.LOG_WARNING)
            return
        
        if self.sync_in_progress:
            RNS.log("IMANAGER : Sync already in progress, skipping request", RNS.LOG_DEBUG)
            return
            
        try:
            # Set sync status
            self.sync_in_progress = True
            
            message = RequestMessage(json={
                'action': 'full_sync_request'
            })
            self.server_channel.send(message)
            RNS.log("IMANAGER : Requested full identity dataset from server", RNS.LOG_INFO)
            
            # Set a timeout for sync completion
            threading.Timer(30.0, self._check_sync_timeout).start()
            
        except Exception as e:
            RNS.log(f"IMANAGER : Error requesting full sync: {str(e)}", RNS.LOG_ERROR)
            self.sync_in_progress = False

    ###
    ### Check is sync timed out
    ###
    def _check_sync_timeout(self):
        """Check if sync is still pending after timeout"""
        if self.sync_in_progress:
            RNS.log("IMANAGER : Sync request timed out", RNS.LOG_WARNING)
            self.sync_in_progress = False

    #### Cache

    # load cached hashes
    def _load_cache(self) -> None:
        try:
            with open(self.cache_file, 'r') as f:
                self.authorized_identities = set(json.load(f))
        except FileNotFoundError:
            RNS.log(f"Database {self.cache_file} not found. Creating a new empty database.", RNS.LOG_DEBUG)
        except json.JSONDecodeError:
            RNS.log(f"Error decoding database file {self.cache_file}. Starting with empty database.", RNS.LOG_ERROR)
            # Create backup of corrupted file if possible
            try:
                if os.path.exists(self.cache_file):
                    backup_path = f"{self.cache_file}.bak.{int(time.time())}"
                    os.rename(self.cache_file, backup_path)
                    RNS.log(f"Created backup of corrupted database at {backup_path}", RNS.LOG_INFO)
            except Exception as e:
                RNS.log(f"Failed to backup corrupted database: {str(e)}", RNS.LOG_ERROR)

    # save hashes to cache
    def _save_cache(self) -> None:
        try:
            # Create a temporary file first to prevent corruption on interrupted writes
            temp_file = f"{self.cache_file}.tmp"
            with open(temp_file, 'w') as f:
                json.dump(list(self.authorized_identities), f)
                
            # Safely replace the original file
            os.replace(temp_file, self.cache_file)
            
            RNS.log(f"Saved {len(self.authorized_identities)} identities to the local cache", RNS.LOG_DEBUG)
            
            # Update merkle tree after changes
            self._update_merkle_tree()
            
        except Exception as e:
            RNS.log(f"Error saving cache: {str(e)}", RNS.LOG_ERROR)

    def _check_suitable_interfaces(self) -> bool:
        """Check if we have suitable network interfaces for syncing"""
        # In a real implementation, you might want to check for appropriate network interfaces
        # For now, we assume all interfaces are suitable
        
        # Check if we're online and can reach the sync server
        if not RNS.Transport.has_path_to(self.sync_server_hash):
            # Request a path to the server
            RNS.Transport.request_path(self.sync_server_hash)
            return False
            
        return True

    # sync with server
    #def _sync_with_server(self) -> bool:
    #    """Perform sync with server, returns True if sync process started"""
    #    try:
    #        # Don't attempt sync if already in progress
    #        if self.sync_in_progress:
    #            return False
                
            # Check if link is active
    #        if not self.server_link or self.server_link.status != RNS.Link.ACTIVE:
    #            RNS.log("Cannot sync: Link not active", RNS.LOG_DEBUG)
    #            self._check_connection()
    #            return False
                
            # Check if we have suitable interfaces
    #        if not self._check_suitable_interfaces():
    #            RNS.log("No suitable network interfaces for sync", RNS.LOG_DEBUG)
    #            return False
            
    #        with self._sync_lock:
                # Check sync strategy based on last sync time
    #            current_time = time.time()
                
                # If we've never synced or it's been a very long time, do a full sync
    #            if self.last_sync_time == 0 or (current_time - self.last_sync_time) > self.SYNC_POLL_INTERVAL * 5:
    #                RNS.log("Performing full sync with server", RNS.LOG_INFO)
    #                self._request_full_sync()
    #            else:
                    # Otherwise, do an incremental sync by first sending a ping
    #                RNS.log("Checking sync status with server", RNS.LOG_DEBUG)
    #                self._send_ping_request()
                
    #            return True
                
    #    except Exception as e:
    #        RNS.log(f"Error initiating sync with server: {str(e)}", RNS.LOG_ERROR)
    #        self.sync_in_progress = False
    #        return False

    def _get_all_hashes(self) -> Set[str]:
        """Get all identity hashes from local cache"""
        return self.authorized_identities.copy()

    ###
    ### Update our hashes with new ones
    ###
    def _update_hashes(self, new_hashes: Set[str]) -> None:
        """Add new identity hashes to authorized set"""
        if not new_hashes:
            return
            
        # Make sure we don't add duplicates by using a set update
        old_count = len(self.authorized_identities)
        self.authorized_identities.update(new_hashes)
        added_count = len(self.authorized_identities) - old_count
        
        if added_count > 0:
            self._save_cache()
            RNS.log(f"IMANAGER : Added {added_count} new identities", RNS.LOG_INFO)
        else:
            RNS.log("IMANAGER : No new identities added (all were duplicates)", RNS.LOG_DEBUG)

    def _remove_hashes(self, removed_hashes: Set[str]) -> None:
        """Remove identity hashes from authorized set"""
        if not removed_hashes:
            return
            
        # Get count before removal
        old_count = len(self.authorized_identities)
        
        # Never remove our own identity or the server identity
        safe_hashes = {RNS.Transport.identity.hash.hex(), self.sync_server_identity}
        filtered_remove = removed_hashes - safe_hashes
        
        # Remove hashes
        self.authorized_identities.difference_update(filtered_remove)
        
        # Calculate how many were actually removed
        removed_count = old_count - len(self.authorized_identities)
        
        if removed_count > 0:
            self._save_cache()
            RNS.log(f"Removed {removed_count} identities", RNS.LOG_INFO)
        else:
            RNS.log("No identities removed", RNS.LOG_DEBUG)
            
    # Public methods for manual operations
    
    def force_sync(self) -> bool:
        """Force a full sync with the server"""
        if self.sync_in_progress:
            RNS.log("Sync already in progress", RNS.LOG_WARNING)
            return False
            
        if not self.server_link or self.server_link.status != RNS.Link.ACTIVE:
            RNS.log("Not connected to server", RNS.LOG_WARNING)
            self._check_connection()
            return False
            
        RNS.log("Forcing full sync with server", RNS.LOG_INFO)
        self._request_full_sync()
        return True
        
    def reconnect(self) -> bool:
        """Force a reconnection to the server"""
        RNS.log("Forcing reconnection to server", RNS.LOG_INFO)
        
        # Clear connection state
        if self.server_link:
            try:
                self.server_link.teardown()
            except:
                pass
            
        self.server_link = None
        self.server_channel = None
        self.connection_status = self.STATUS_DISCONNECTED
        self.connection_retry_count = 0
        self.sync_in_progress = False
        
        # Attempt to reconnect
        self._sync_establish_link()
        return True
        
    def add_identity(self, identity_hash: str) -> bool:
        """Manually add an identity hash"""
        if not identity_hash or len(identity_hash) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH // 8) * 2):
            RNS.log(f"Invalid identity hash format: {identity_hash}", RNS.LOG_ERROR)
            return False
            
        RNS.log(f"Manually adding identity: {identity_hash}", RNS.LOG_INFO)
        self._update_hashes({identity_hash})
        return True
        
    def remove_identity(self, identity_hash: str) -> bool:
        """Manually remove an identity hash"""
        if identity_hash == RNS.Transport.identity.hash.hex():
            RNS.log("Cannot remove own identity", RNS.LOG_WARNING)
            return False
            
        if identity_hash == self.sync_server_identity:
            RNS.log("Cannot remove sync server identity", RNS.LOG_WARNING)
            return False
            
        if identity_hash not in self.authorized_identities:
            RNS.log(f"Identity not found: {identity_hash}", RNS.LOG_WARNING)
            return False
            
        RNS.log(f"Manually removing identity: {identity_hash}", RNS.LOG_INFO)
        self._remove_hashes({identity_hash})
        return True