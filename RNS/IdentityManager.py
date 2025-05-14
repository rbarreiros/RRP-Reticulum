import os
import threading
import RNS
import json
import asyncio
import time
import traceback

from RNS.vendor import umsgpack
from typing import Set
from .Merkle import MerkleNode, MerkleTree

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
        self.master_server_hash = config.get('master_server_hash')
        if not self.master_server_hash:
            raise IdentityManagerException("No master server hash configured.")

        if len(self.master_server_hash) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH // 8) * 2):
            raise IdentityManagerException("Master server hash length is invalid.")

        if isinstance(self.master_server_hash, str):
            self.master_server_hash = bytes.fromhex(self.master_server_hash)

        # Start reticulum master server Link
        self.master_destination = None
        self.master_link = None
        self.master_channel = None
        self._initialize_reticulum_client()


        # Should probably enforce our own hash right ? right ??
        #RNS.log(f"Our own hash: {RNS.Transport.identity.hash.hex()}", RNS.LOG_DEBUG)
        #
        # debug identities
        #self.authorized_identities.add(RNS.Transport.identity.hash)

        # Cache paths
        self.cache_dir = os.path.join(RNS.Reticulum.cachepath, 'idmanager')
        self.cache_file = os.path.join(self.cache_dir, 'idmanager.json')

        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)

        self._load_cache()

        # Make sure we're in
        if RNS.Transport.identity.hash not in self.authorized_identities:
            self.authorized_identities.add(RNS.Transport.identity.hash.hex())

        # Obviously, add the master server to the list of authorized identities
        self.authorized_identities.add(self.master_server_hash)

        # Remove, test
        self.authorized_identities.add('df160eed0bdecba906b2040ac82226c2')
        self.authorized_identities.add('72afa1832f38efa345aa34be70db46ef')

        # Threading stuff
        self._stop_event = threading.Event()
        self._sync_thread = None
        self._sync_lock = threading.Lock()

        RNS.log(f"Identity Manager loaded {len(self.authorized_identities)} identities.", RNS.LOG_INFO)
        

    def start(self) -> None:
        # Start the identity sync thread
        if self._stop_event.is_set():
            RNS.log("Already running", RNS.LOG_DEBUG)
            return 
        
        self._stop_event.clear()

        # Create event loop in new thread
        def run_async_loop():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._sync_loop())
            loop.close()
        
        #self._sync_thread = threading.Thread(target=run_async_loop)
        #self._sync_thread.daemon = True

        RNS.log("Starting identity sync thread.", RNS.LOG_DEBUG)
        #self._sync_thread.start()

    def stop(self):
        # Stop the identity sync thread
        self._stop_event.set()
        if self._sync_thread:
            self._sync_thread.join()
            RNS.log("Identity Manager sync thread stopped", RNS.LOG_INFO)

    def is_authorized(self, packet: bytes) -> bool:
        from pprint import pprint

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
            server = RNS.Identity.recall(self.master_server_hash)

            if not server:
                RNS.Transport.request_path(self.master_server_hash)
                server = RNS.Identity.recall(self.master_server_hash)

                if not server:
                    return

            self.master_destination = RNS.Destination(
                server,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                "idserver",
                "sync"
            )

            self.master_link = RNS.Link(self.master_destination)
            self.master_link.set_link_established_callback(self._sync_server_link_established)
            self.master_link.set_link_closed_callback(self._sync_server_link_closed)
        except Exception as e:
            RNS.log(f"Unable to create link connection to master server {e.with_traceback()}", RNS.LOG_DEBUG)

    def _sync_server_link_established(self) -> None:
        self.master_channel = self.master_link.get_channel()
        self.master_channel.register_message_type(SyncMessage)
        self.master_channel.add_message_handler(self._sync_channel_msg_received)
        self.master_link.identify(RNS.Transport.identity)
        RNS.log(f"Link established with master server")

    def _sync_server_link_closed(self) -> None:
        # Link is down, check why, warn the user, try to reconnect again on each sync attempt
        if self.master_link.teardown_reason == RNS.Link.TIMEOUT:
            RNS.log("Link no master server disconnected, timed out...", RNS.LOG_DEBUG)
        elif self.master_link.teardown_reason == RNS.Link.DESTINATION_CLOSED:
            RNS.log("Link disconnected by master server.", RNS.LOG_DEBUG)
        else:
            RNS.log("Link to master server closed by an unknown reason.", RNS.LOG_DEBUG)

    def _sync_channel_msg_received(self, message: SyncMessage) -> None:
        try:
            # Validate
            if not hasattr(message, 'json'):
                RNS.log("Received invalid message without JSON", RNS.LOG_DEBUG)
                return

            msg_json = message.json
            RNS.log(f"Received master server message: {json.dumps(msg_json)}", RNS.LOG_DEBUG)

            if 'cmd' not in msg_json:
                RNS.log("Received message without command", RNS.LOG_DEBUG)
                return

            cmd = msg_json['cmd']
        
            if cmd == SyncMessage.CMD_GET_ROOT:
                # Return the root hash of the current identity set
                merkle_tree = self._get_merkle_tree()
                response = {
                    'root_hash': merkle_tree.root.hash.hex() if merkle_tree.root else None,
                    'status': ''
                }
                self._send_response(message, response)

            elif cmd == SyncMessage.CMD_GET_MERKLE:
                # Return the entire Merkle tree
                merkle_tree = self._get_merkle_tree()
                response = {
                    'merkle_tree': merkle_tree.to_dict(),
                    'status': ''
                }
                self._send_response(message, response)

            elif cmd == SyncMessage.CMD_GET_HASHES:
                # Return all current identity hashes
                hashes = self._get_all_hashes()
                response = {
                    'hashes': list(hashes),
                    'status': ''
                }
                self._send_response(message, response)

            elif cmd == SyncMessage.CMD_GET_DELETED:
                # Implement logic to return deleted hashes if tracking is implemented
                response = {
                    'deleted_hashes': [],
                    'status': ''
                }
                self._send_response(message, response)

            elif cmd == SyncMessage.CMD_GET_ALL:
                # Comprehensive sync response
                merkle_tree = self._get_merkle_tree()
                hashes = self._get_all_hashes()
                response = {
                    'root_hash': merkle_tree.root.hash.hex() if merkle_tree.root else None,
                    'merkle_tree': merkle_tree.to_dict(),
                    'hashes': list(hashes),
                    'status': ''
                }
                self._send_response(message, response)
        except Exception as e:
            RNS.log(f"Error processing sync message: {str(e)}", RNS.LOG_ERROR)
            self._send_response(message, {'status': str(e)})

    def _send_response(self, original_message: SyncMessage, response: dict) -> None:
        try:
            response_msg = SyncMessage(json=response)
        
            if self.master_channel:
                self.master_channel.send(response_msg)
            else:
                RNS.log("Cannot send response: master channel not established", RNS.LOG_ERROR)
        except Exception as e:
            RNS.log(f"Error sending sync response: {str(e)}", RNS.LOG_ERROR)

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

    def _check_suitable_interfaces(self) -> bool:
        return False

    # Send a sync request
    async def _send_sync_request(self, sync_msg : SyncMessage, timeout: float = 30.0) -> dict:
        try:
            response_future = asyncio.Future()

            # Temporary message handler
            def temp_handler(message):
                try:
                    # Validate message
                    if not hasattr(message, 'json'):
                        return
                
                    # Check for status and command match
                    if 'status' in message.json and message.json['status']:
                        # Error occurred
                        RNS.log(f"Sync error: {message.json['status']}", RNS.LOG_ERROR)
                    
                        if not response_future.done():
                            response_future.set_exception(Exception(message.json['status']))
                        return

                    # Success
                    if not response_future.done():
                        response_future.set_result(message.json)
                except Exception as e:
                    if not response_future.done():
                        response_future.set_exception(e)

            # Register temp handler
            handler = self.master_channel.add_message_handler(temp_handler)

            # Send the message
            self.master_channel.send(sync_msg)

            # Wait for response with timeout
            try:
                response = await asyncio.wait_for(response_future, timeout)
                return response
            except asyncio.TimeoutError:
                RNS.log("Sync request timed out", RNS.LOG_ERROR)
                return {}
            finally:
                # Remove the temporary handler
                self.master_channel.remove_message_handler(handler)
        except Exception as e:
            RNS.log(f"Error sending sync request: {str(e)}", RNS.LOG_ERROR)
            return {}


    # sync with server
    async def _sync_with_server(self) -> bool:
        return True
    
    # Sync thread
    async def _sync_loop(self) -> None:
        # Main sync loop
        while not self._stop_event.is_set():
            try:
                # Check link
                if self.master_link.status != RNS.Link.ACTIVE:
                    self._sync_establish_link()
                    await asyncio.sleep(self.RETRY_INTERVAL)
                    continue

                # Only sync over appropriate interfaces
                if not self._check_suitable_interfaces():
                    await asyncio.sleep(self.RETRY_INTERVAL)
                    continue

                success = False
                retries = 0
                
                while not success and retries < self.MAX_RETRIES:
                    success = await self._sync_with_server()
                    if success:
                        #self.sync_status.last_sync_time = time.time()
                        self._save_cache()
                    else:
                        retries += 1
                        if retries < self.MAX_RETRIES:
                            await asyncio.sleep(self.RETRY_INTERVAL)

                if success:
                    RNS.log("Sync completed successfully", RNS.LOG_DEBUG)
                    await asyncio.sleep(self.SYNC_INTERVAL)
                else:
                    RNS.log("Sync failed after max retries", RNS.LOG_WARNING)
                    await asyncio.sleep(self.RETRY_INTERVAL)

            except Exception as e:
                RNS.log(f"Error in sync loop: {str(e)}", RNS.LOG_ERROR)
                await asyncio.sleep(self.RETRY_INTERVAL)

    def _get_merkle_tree(self) -> MerkleTree:
        return MerkleTree(self.authorized_identities)
    
    def _update_hashes(self, new_hashes: Set[str]) -> None:
        self.authorized_identities.update(new_hashes)
        self._save_cache()

    def _remove_hashes(self, removed_hashes: Set[str]) -> None:
        self.authorized_identities.difference_update(removed_hashes)
        self._save_cache()

    def _get_all_hashes(self) -> Set[str]:
        return self.authorized_identities.copy()

    