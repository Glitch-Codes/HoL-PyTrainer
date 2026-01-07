import struct
import utility

class UnlimitedFuel:
    def __init__(self, process, executible, proc_handle, unlimited_fuel_addr):
        self.process = process
        self.executible = executible
        self.proc_handle = proc_handle
        self.unlimited_fuel_addr = unlimited_fuel_addr
        self.enabled = False
        self.code_cave = None
        self.fuel_addr = None
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
        
        self.code_cave = utility.allocCodeCave(self.proc_handle, self.unlimited_fuel_addr)
        if not self.code_cave:
            return False
        print(f"Using code cave at: {hex(self.code_cave)}")

        # Patch the opcode
        try:
            # Build code cave with fuel value injection:
            # Structure: [fuel float (4 bytes)][load xmm0 (8 bytes)][original instruction (8 bytes)][jump back (5 bytes)]
            
            print(f"Building code cave with fuel value injection")
            
            # Fuel value at the beginning of code cave
            fuel_value = 50.0
            fuel_bytes = struct.pack('<f', fuel_value)

            # Build code cave instructions:
            # cave+0: fuel float (50.0)
            # cave+4: movss xmm0,[rip+offset] - loads fuel value
            # cave+12: movss [rcx+000010D8],xmm0 - original instruction
            # cave+20: jmp return
            
            # Build instruction to load fuel value into xmm0: movss xmm0,[rip+offset]
            # The instruction is at cave+4, and is 8 bytes long (F3 0F 10 05 [4-byte offset])
            # After the instruction executes, RIP will be at cave+12
            # We want to load from cave+0, so offset = cave+0 - cave+12 = -12
            load_instruction_addr = self.code_cave + 4
            rip_after_load = load_instruction_addr + 8
            rip_offset = self.code_cave - rip_after_load  # Should be -12
            
            print(f"  Fuel value at: {hex(self.code_cave)}")
            print(f"  Load instruction at: {hex(load_instruction_addr)}")
            print(f"  RIP after load: {hex(rip_after_load)}")
            print(f"  RIP offset to fuel: {rip_offset}")
            
            # movss xmm0,[rip+offset] = F3 0F 10 05 [4-byte signed offset]
            rip_offset_bytes = rip_offset.to_bytes(4, 'little', signed=True)
            load_instruction = bytes([0xF3, 0x0F, 0x10, 0x05]) + rip_offset_bytes
            
            # Original instruction
            original_instruction = self.original_bytes
            
            # Calculate jump back to address after original hook
            return_addr = self.unlimited_fuel_addr + 8
            cave_end = self.code_cave + 4 + 8 + 8 + 5  # fuel + load + original + jump
            jmp_back_offset = return_addr - cave_end
            jmp_back_bytes = bytes([0xE9]) + jmp_back_offset.to_bytes(4, 'little', signed=True)
            
            # Assemble cave code: fuel + load instruction + original instruction + jump back
            cave_code = fuel_bytes + load_instruction + original_instruction + jmp_back_bytes
            
            print(f"Writing {len(cave_code)} bytes to code cave:")
            print(f"  Fuel float (0-3): {fuel_bytes.hex()}")
            print(f"  Load xmm0 (4-11): {load_instruction.hex()}")
            print(f"  Original instruction (12-19): {original_instruction.hex()}")
            print(f"  Jump back (20-24): {jmp_back_bytes.hex()}")
            
            utility.patchBytes(self.proc_handle, ''.join(f'{b:02x}' for b in cave_code), self.code_cave, len(cave_code))
            
            # Create 5-byte jump from original location to code cave (jump to cave+4, skip the fuel float)
            jmp_to_offset = (self.code_cave + 4) - (self.unlimited_fuel_addr + 5)
            jmp_bytes = bytes([0xE9]) + jmp_to_offset.to_bytes(4, 'little', signed=True) + bytes([0x90, 0x90, 0x90])  # 3 NOPs to fill 8 bytes
            
            print(f"Writing hook at {hex(self.unlimited_fuel_addr)}: {jmp_bytes.hex()}")
            print(f"  Jump to offset: {jmp_to_offset}")
            utility.patchBytes(self.proc_handle, ''.join(f'{b:02x}' for b in jmp_bytes), self.unlimited_fuel_addr, 8)
            

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
        
        # Free allocated memory
        if self.code_cave:
            utility.freeMemory(self.proc_handle, self.code_cave)
            self.code_cave = None

        self.enabled = False
        print("Unlimited Fuel disabled!")

