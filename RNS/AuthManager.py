import threading
import time
import json
import hashlib
import RNS
from RNS.Interfaces.TCPInterface import TCPInterface, TCPServerInterface
from RNS.Interfaces.UDPInterface import UDPInterface
from RNS.Interfaces.BackboneInterface import BackboneInterface, BackboneClientInterface
import logging
from typing import Dict, Set, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime
import asyncio
import os

@dataclass
class SyncStatus:
    last_sync_time: float
    last_sync_hash: str
    server_token: Optional[str]
    is_registered: bool

class AuthManagerException(Exception):
    pass

class AuthManager:
    SYNC_INTERVAL = 300  # 5 minutes between syncs
    RETRY_INTERVAL = 60  # 1 minute between retries on failure
    MAX_RETRIES = 3
    master_server_hash = ''

    def __init__(self, config):
        """Initialize AuthManager with configuration from reticulum.config"""
        self.config = config
        self.SYNC_INTERVAL = config.get('sync_interval', 300)
        self.RETRY_INTERVAL = config.get('retry_interval', 60)
        self.MAX_RETRIES = config.get('max_retries', 3)

        # master server identity exists ?
        self.master_server_hash = config.get('master_server_hash')
        if not self.master_server_hash:
            raise AuthManagerException("Master server hash not configured")

        # is it correct ?
        dest_len = (RNS.Reticulum.TRUNCATED_HASHLENGTH // 8) * 2
        if(len(self.master_server_hash) != dest_len):
            raise AuthManagerException("Master server hash length is invalid, must be {hex} hexadecimal characters ({byte} bytes).".format(hex = dest_len, byte = dest_len / 2))

        # Convert hex string to bytes if needed
        if isinstance(self.master_server_hash, str):
            self.master_server_hash = bytes.fromhex(self.master_server_hash)

        # Initialize sync status
        self.sync_status = SyncStatus(
            last_sync_time = 0,
            last_sync_hash = "",
            server_token = None,
            is_registered = False
        )

        # Initialize other attributes
        self.authorized_identities = set()
        self._stop_event = threading.Event()
        self._sync_thread = None
        self._sync_lock = threading.Lock()
        
        # Set up cache paths
        self.cache_dir = os.path.join(RNS.Reticulum.cachepath, "auth")
        self.cache_file = os.path.join(self.cache_dir, "auth_cache.json")
        
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
        
        # Load cached data
        self._load_cache()
        RNS.log(f"AuthManager - Loaded {len(self.authorized_identities)} identities.", RNS.LOG_DEBUG)
        
    def start(self):
        """Start the auth manager"""
        if self._stop_event.is_set():
            RNS.log("Already running", RNS.LOG_DEBUG)
            return  # Already running
        
        self._stop_event.clear()

        # Create event loop in new thread
        def run_async_loop():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._sync_loop())
            loop.close()
        
        self._sync_thread = threading.Thread(target=run_async_loop)
        self._sync_thread.daemon = True

        RNS.log("Starting identity sync thread.", RNS.LOG_DEBUG)
        self._sync_thread.start()

    def stop(self):
        """Stop the sync thread"""
        self._stop_event.set()
        if self._sync_thread:
            self._sync_thread.join()
            RNS.log("AuthManager sync thread stopped", RNS.LOG_INFO)

    def is_authorized(self, identity_hash: bytes) -> bool:
        """Check if an identity is authorized"""
        with self._sync_lock:
            return identity_hash in self.authorized_identities

    def _calculate_list_hash(self) -> str:
        """Calculate hash of current identity list"""
        sorted_identities = sorted(self.authorized_identities)
        concatenated = b''.join(sorted_identities)
        return hashlib.sha256(concatenated).hexdigest()

    def _load_cache(self):
        """Load cached identities and sync status"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    self.authorized_identities = set(bytes.fromhex(h) for h in data.get('identities', []))

                    # Update sync status from cache
                    self.sync_status.last_sync_hash = data.get('last_sync_hash', '')
                    self.sync_status.server_token = data.get('server_token')
                    self.sync_status.is_registered = data.get('is_registered', False)
                    self.sync_status.last_sync_time = data.get('last_sync_time', 0)

                    RNS.log(f"Loaded {len(self.authorized_identities)} cached identities", RNS.LOG_INFO)
        except Exception as e:
            RNS.log(f"Error loading auth cache: {str(e)}", RNS.LOG_ERROR)

    def _save_cache(self):
        """Save current identities and sync status to cache"""
        try:
            data = {
                'identities': [h.hex() for h in self.authorized_identities],
                'last_sync_hash': self.sync_status.last_sync_hash,
                'server_token': self.sync_status.server_token,
                'is_registered': self.sync_status.is_registered,
                'last_sync_time': self.sync_status.last_sync_time,
                'last_update': datetime.now().isoformat()
            }
            with open(self.cache_file, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            RNS.log(f"Error saving auth cache: {str(e)}", RNS.LOG_ERROR)

    async def _register_with_server(self) -> bool:
        """Register this node with the master server"""
        RNS.log("Attempting master identity server registration.")
        try:
            if RNS.Transport.has_path(self.master_server_hash):
                server_identity = RNS.Identity.recall(self.master_server_hash)

                if not server_identity:
                    raise AuthManagerException("Could not get master server identity")

                # Create outbound destination to master server using its identity
                self.master_server = RNS.Destination(
                    server_identity,          # Server's identity that we recalled
                    RNS.Destination.OUT,      # Direction - we're connecting to server
                    RNS.Destination.SINGLE,   # Type - encrypted single destination
                    "auth",                   # App name - must match server's app name
                    "master"                  # Aspect - must match server's aspect
                )

                registration_data = {
                    'client_identity': RNS.Transport.identity.hash.hex(),
                    'client_type': 'node',
                    'timestamp': time.time()
                }
            
                # Send registration request
                packet = RNS.Packet(
                    self.master_server,
                    json.dumps(registration_data).encode(),
                    RNS.Packet.DATA
                )
            
                # Send registration request and wait for response
                response = await self._wait_for_response(packet)
                if not response:
                    return False

                try:
                    response_data = json.loads(response.data.decode())
                    if 'token' in response_data:
                        self.sync_status.server_token = response_data['token']
                        self.sync_status.is_registered = True
                        self._save_cache()
                        RNS.log("Successfully registered with master server", RNS.LOG_INFO)
                        return True
                
                    return False
                except Exception as e:
                    RNS.log(f"Error parsing registration response: {str(e)}", RNS.LOG_ERROR)
                    return False
            else:
                RNS.log("Destination is not yet known. Requesting path...")
                RNS.Transport.request_path(self.master_server_hash)
                return False
        except Exception as e:
            RNS.log(f"Registration failed: {str(e)}", RNS.LOG_ERROR)
            return False

    async def _send_request_to_server(self, action: str, data: dict) -> Optional[dict]:
        """Send a request to the master server and verify response"""
        try:
            if RNS.Transport.has_path(self.master_server_hash):
                server_identity = RNS.Identity.recall(self.master_server_hash)
            
                if not server_identity:
                    raise AuthManagerException("Could not get master server identity")

                # Create outbound destination to master server using its identity
                self.master_server = RNS.Destination(
                    server_identity,          # Server's identity that we recalled
                    RNS.Destination.OUT,      # Direction - we're connecting to server
                    RNS.Destination.SINGLE,   # Type - encrypted single destination
                    "auth",                   # App name - must match server's app name
                    "master"                  # Aspect - must match server's aspect
                )

                request_data = {
                    'action': action,
                    'data': data,
                    'token': self.sync_status.server_token
                }
            
                # Create packet and send to master server
                packet = RNS.Packet(
                    self.master_server,
                    json.dumps(request_data).encode(),
                    RNS.Packet.DATA
                )
            
                # Wait for response
                response = await self._wait_for_response(packet)
            
                if response:
                    # Verify response signature/token
                    if self._verify_server_response(response):
                        return json.loads(response.data.decode())
            
                return None
            else:
                RNS.log("Destination is not yet known. Requesting path...")
                RNS.Transport.request_path(self.master_server_hash)

        except Exception as e:
            RNS.log(f"Error sending request to server: {str(e)}", RNS.LOG_ERROR)
            return None

    def _verify_server_response(self, response: RNS.Packet) -> bool:
        """Verify that a response came from the master server"""
        try:
            response_data = json.loads(response.data.decode())
            if not self.sync_status.server_token:
                # If we don't have a token yet, only accept registration responses
                return response_data.get('action') == 'register'
            
            # Verify the response token matches our stored token
            return response_data.get('token') == self.sync_status.server_token
        except:
            return False

    async def _sync_with_server(self) -> bool:
        """Perform a sync with the master server"""
        try:
            # First check if we need to register
            if not self.sync_status.is_registered:
                if not await self._register_with_server():
                    return False

            # Get current server hash
            response = await self._send_request_to_server('get_hash', {
                'client_hash': self._calculate_list_hash()
            })
            
            if not response:
                return False

            server_hash = response.get('hash')
            
            # If hashes match, we're up to date
            if server_hash == self.sync_status.last_sync_hash:
                RNS.log("Indentities sync up to date.")
                return True

            # Request updates
            RNS.log("Identity sync required. Requesting identity changes.")
            response = await self._send_request_to_server('get_updates', {
                'last_sync_hash': self.sync_status.last_sync_hash
            })
            
            if response and 'updates' in response:
                # Apply updates
                with self._sync_lock:
                    self._apply_updates(response['updates'])
                    self.sync_status.last_sync_hash = server_hash
                    self._save_cache()
                return True

            # If partial update failed, get full list
            response = await self._send_request_to_server('get_full_list', {})
            
            if response and 'identities' in response:
                with self._sync_lock:
                    self.authorized_identities = set(bytes.fromhex(h) for h in response['identities'])
                    self.sync_status.last_sync_hash = server_hash
                    self._save_cache()
                return True

            return False
        except Exception as e:
            RNS.log(f"Sync failed: {str(e)}", RNS.LOG_ERROR)
            return False

    def _apply_updates(self, updates: Dict[str, List[str]]):
        """Apply updates to the identity list"""
        for action, identities in updates.items():
            if action == 'add':
                self.authorized_identities.update(bytes.fromhex(h) for h in identities)
            elif action == 'remove':
                self.authorized_identities.difference_update(bytes.fromhex(h) for h in identities)

    async def _sync_loop(self):
        """Main sync loop"""
        while not self._stop_event.is_set():
            try:
                # Only sync over appropriate interfaces
                if not self._check_suitable_interfaces():
                    await asyncio.sleep(self.RETRY_INTERVAL)
                    continue

                success = False
                retries = 0
                
                while not success and retries < self.MAX_RETRIES:
                    success = await self._sync_with_server()
                    if success:
                        self.sync_status.last_sync_time = time.time()
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

    def _check_suitable_interfaces(self) -> bool:
        """Check if we have suitable interfaces for syncing"""
        suitable_interfaces = [
            i for i in RNS.Transport.interfaces
            if isinstance(i, (TCPInterface, TCPServerInterface, UDPInterface, BackboneInterface, BackboneClientInterface))
        ]
        RNS.log(f"AuthManager - found {len(suitable_interfaces)} suitable interfaces to sync identities.", RNS.LOG_DEBUG)
        return len(suitable_interfaces) > 0

    async def _wait_for_response(self, packet, timeout=10):
        """Wait for a response from the server"""
        try:
            # Create a future to store the response
            response_future = asyncio.Future()
            
            # Create a packet receipt
            receipt = packet.send()
            if not receipt:
                RNS.log("Failed to send packet", RNS.LOG_ERROR)
                return None

            def response_handler(response_packet):
                if not response_future.done():
                    response_future.set_result(response_packet)
            
            # Set the delivery callback
            receipt.set_delivery_callback(response_handler)
            
            # Set timeout
            receipt.set_timeout(timeout)
            
            # Wait for response with timeout
            try:
                response = await asyncio.wait_for(response_future, timeout)
                return response
            except asyncio.TimeoutError:
                RNS.log("Timeout waiting for server response", RNS.LOG_ERROR)
                return None
            
        except Exception as e:
            RNS.log(f"Error waiting for server response: {str(e)}", RNS.LOG_ERROR)
            return None

