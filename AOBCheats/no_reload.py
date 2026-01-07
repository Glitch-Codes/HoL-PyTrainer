import utility

class NoReload:
    def __init__(self, process, executible, proc_handle, no_reload_addr):
        self.process = process
        self.executible = executible
        self.proc_handle = proc_handle
        self.no_reload_addr = no_reload_addr
        self.enabled = False
        self.original_bytes = None
        
    def enable(self):
        """Enable no reload by replacing weapon reload instruction"""
        if self.enabled:
            return True
            
        #AOB scan for the reload instruction
        #Pattern: 89 87 E0 00 00 00 (mov [rdi+000000E0],eax) + 48 85 F6 (test rsi,rsi)
        #pattern = "89 87 E0 00 00 00 48 85 F6"
        #self.no_reload_addr = utility.aobScan(self.process, pattern, self.executible)

        # Get address by pointer
        #self.no_reload_addr = self.base_address + 0x18F4416
        
        if not self.no_reload_addr:
            return False
        
        # Save original bytes (6 bytes)
        self.original_bytes = self.process.read_bytes(self.no_reload_addr, 6)
        print(f"Original bytes: {self.original_bytes.hex()}")
        
         # Patch the opcode to NOPs
        try:
            # NOP out the instruction (replace with 6 NOPs: 90 90 90 90 90 90 using utility function nopBytes)
            utility.nopBytes(self.proc_handle, self.no_reload_addr, 6)
            self.enabled = True
            print("No reload enabled!")
            return True
        except Exception as e:
            print(f"Failed to enable no reload: {e}")
            return False
    
    def disable(self):
        """Disable no reload by restoring original bytes"""
        if not self.enabled:
            return

        # Restore original bytes
        if self.original_bytes and self.no_reload_addr:
            utility.patchBytes(self.proc_handle, ''.join(f'{b:02x}' for b in self.original_bytes), self.no_reload_addr, len(self.original_bytes))

        self.enabled = False
        print("No reload disabled!")

