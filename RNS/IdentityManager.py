import os
import threading
import RNS


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


    def __init__(self, config):
        self.config = config
        self.SYNC_POLL_INTERVAL = config.get('sync_interval', 300)
        self.SYNC_RETRY_INTERVAL = config.get('retry_interval', 60)
        self.SYNC_MAX_RETRIES = config.get('max_retries', 3)

        self.master_server_hash = config.get('master_server_hash')
        if not self.master_server_hash:
            raise IdentityManagerException("No master server hash configured.")

        if len(self.master_server_hash) != ((RNS.Reticulum.TRUNCATED_HASHLENGTH // 8) * 2):
            raise IdentityManagerException("Master server hash length is invalid.")

        if isinstance(self.master_server_hash, str):
            self.master_server_hash = bytes.fromhex(self.master_server_hash)

        # The identities that are authorized 
        self.authorized_identities = set()

        RNS.log(f"Our own hash: {RNS.Transport.identity.hash.hex()}", RNS.LOG_DEBUG)

        # debug identities
        self.authorized_identities.add("8d41c23e99fb08d4ad1169bd78e703d7")

        # Cache paths
        self.cache_dir = os.path.join(RNS.Reticulum.cachepath, 'idmanager')
        self.cache_file = os.path.join(self.cache_dir, 'idmanager.json')

        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)

        # Threading stuff

        # Locking of authorized identities
        self._sync_lock = threading.Lock()

        #self._load_cache()
        RNS.log(f"Identity Manager loaded {len(self.authorized_identities)} identities.", RNS.LOG_INFO)

    def start(self):
        # Start the identity sync thread
        pass

    def stop(self):
        # Stop the identity sync thread
        pass

    def is_authorized(self, hash: bytes) ->bool:
        with self._sync_lock:
            return hash in self.authorized_identities



    # Sync thread
    async def _sync_loop(self):
        pass
        