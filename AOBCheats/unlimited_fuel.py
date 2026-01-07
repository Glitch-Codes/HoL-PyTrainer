import utility

class UnlimitedFuel:
    def __init__(self, process, executible, proc_handle, unlimited_fuel_addr):
        self.process = process
        self.executible = executible
        self.proc_handle = proc_handle
        self.unlimited_fuel_addr = unlimited_fuel_addr
        self.enabled = False
        self.code_cave = None
        self.original_bytes = None
        
    def enable(self):
        """Enable no reload by replacing weapon reload instruction"""
        if self.enabled:
            return True
            
        #AOB scan for the reload instruction
        #Pattern: F3 0F 11 81 D8 10 00 00 (movss [rcx+000010D8],xmm0)
        #pattern = "F3 0F 11 81 D8 10 00 00"
        #self.fuel_addr = utility.aobScan(self.process, pattern, self.executible)

        # Get address by pointer
        #self.fuel_addr = self.base_address + 0x18F4416
        
        if not self.unlimited_fuel_addr:
            return False
        
        # Save original bytes (8 bytes)
        self.original_bytes = self.process.read_bytes(self.unlimited_fuel_addr, 8)
        print(f"Original bytes: {self.original_bytes.hex()}")
        
        # Get code cave for new instructions
        self.code_cave = utility.findCodeCave(self.process, self.unlimited_fuel_addr, len(self.original_bytes))
        if not self.code_cave:
            print("Failed to find code cave for unlimited fuel")
            return False
        print(f"Using code cave at: {hex(self.code_cave)}")
    
        # Patch the opcode
        try:
            self.enabled = True
            print("Unlimited Fuel enabled!")
            return True
        except Exception as e:
            print(f"Failed to enable unlimited fuel: {e}")
            if self.code_cave:
                utility.freeMemory(self.proc_handle, self.code_cave)
            return False
    
    def disable(self):
        """Disable unlimited fuel by restoring original bytes"""
        if not self.enabled:
            return

        # Restore original bytes
        if self.original_bytes and self.unlimited_fuel_addr:
            utility.patchBytes(self.proc_handle, ''.join(f'{b:02x}' for b in self.original_bytes), self.unlimited_fuel_addr, len(self.original_bytes))

        self.enabled = False
        print("Unlimited Fuel disabled!")

