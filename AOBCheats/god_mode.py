import struct
import utility

class GodMode:
    def __init__(self, process, executible, proc_handle, god_mode_addr):
        self.process = process
        self.executible = executible
        self.proc_handle = proc_handle
        self.god_mode_addr = god_mode_addr
        self.enabled = False
        self.code_cave = None
        self.original_bytes = None
        
    def enable(self):
        """Enable god mode by replacing the health decrement instructions"""
        if self.enabled:
            return True
        
        if not self.god_mode_addr:
            return False
        
        # Save original bytes (5 bytes: F3 0F 11 41 0C)
        self.original_bytes = self.process.read_bytes(self.god_mode_addr, 5)
        print(f"Original bytes: {self.original_bytes.hex()}")
        
        self.code_cave = utility.allocCodeCave(self.proc_handle, self.god_mode_addr)
        if not self.code_cave:
            return False
        print(f"Using code cave at: {hex(self.code_cave)}")
        
        # Assemble the code cave
        try:
            # Build code cave:
            # Structure: [health float (4 bytes)][check and load (varies)][original instruction (5 bytes)][jump back (5 bytes)]
            
            print(f"Building code cave with god mode")
            
            # Health value at the beginning of code cave
            health_value = 120.0
            health_bytes = struct.pack('<f', health_value)
            
            # Build the conditional check and load instructions:
            # cmp [rbx+14],#505 (48 81 7B 14 05 05 00 00) - 8 bytes
            # jne code (75 0A) - 2 bytes  
            # movss xmm0,[rip+offset] (F3 0F 10 05 [4-byte offset]) - 8 bytes
            # Total: 18 bytes before original instruction
            
            # Instruction addresses:
            # cave+0: health float
            # cave+4: cmp [rbx+14],#505
            # cave+12: jne code (jump to original instruction if not player)
            # cave+14: movss xmm0,[rip+offset] (load health if player)
            
            # cmp [rbx+14],#505
            cmp_instruction = bytes([0x48, 0x81, 0x7B, 0x14, 0x05, 0x05, 0x00, 0x00])
            
            # jne code - jump 10 bytes forward (skip the movss load instruction)
            jne_instruction = bytes([0x75, 0x0A])
            
            # movss xmm0,[rip+offset] - load health value
            # Instruction at cave+14, RIP after = cave+22
            # Target is cave+0, so offset = cave+0 - cave+22 = -22
            load_instruction_addr = self.code_cave + 14
            rip_after_load = load_instruction_addr + 8
            rip_offset = self.code_cave - rip_after_load
            
            print(f"  Health value at: {hex(self.code_cave)}")
            print(f"  Load instruction at: {hex(load_instruction_addr)}")
            print(f"  RIP offset to health: {rip_offset}")
            
            rip_offset_bytes = rip_offset.to_bytes(4, 'little', signed=True)
            load_instruction = bytes([0xF3, 0x0F, 0x10, 0x05]) + rip_offset_bytes
            
            # Original instruction: movss [rcx+0C],xmm0
            original_instruction = self.original_bytes
            
            # Calculate jump back to address after original hook
            return_addr = self.god_mode_addr + 5
            cave_end = self.code_cave + 4 + 8 + 2 + 8 + 5 + 5  # health + cmp + jne + load + original + jump
            jmp_back_offset = return_addr - cave_end
            jmp_back_bytes = bytes([0xE9]) + jmp_back_offset.to_bytes(4, 'little', signed=True)
            
            # Assemble cave code: health + cmp + jne + load + original + jump back
            cave_code = health_bytes + cmp_instruction + jne_instruction + load_instruction + original_instruction + jmp_back_bytes
            
            print(f"Writing {len(cave_code)} bytes to code cave:")
            print(f"  Health float (0-3): {health_bytes.hex()}")
            print(f"  CMP instruction (4-11): {cmp_instruction.hex()}")
            print(f"  JNE instruction (12-13): {jne_instruction.hex()}")
            print(f"  Load xmm0 (14-21): {load_instruction.hex()}")
            print(f"  Original instruction (22-26): {original_instruction.hex()}")
            print(f"  Jump back (27-31): {jmp_back_bytes.hex()}")
            
            utility.patchBytes(self.proc_handle, ''.join(f'{b:02x}' for b in cave_code), self.code_cave, len(cave_code))
            
            # Create 5-byte jump from original location to code cave (jump to cave+4, skip the health float)
            jmp_to_offset = (self.code_cave + 4) - (self.god_mode_addr + 5)
            jmp_bytes = bytes([0xE9]) + jmp_to_offset.to_bytes(4, 'little', signed=True)
            
            print(f"Writing hook at {hex(self.god_mode_addr)}: {jmp_bytes.hex()}")
            print(f"  Jump to offset: {jmp_to_offset}")
            utility.patchBytes(self.proc_handle, ''.join(f'{b:02x}' for b in jmp_bytes), self.god_mode_addr, 5)

            self.enabled = True
            print("God mode enabled!")
            return True
            
        except Exception as e:
            print(f"Failed to enable god mode: {e}")
            if self.code_cave:
                utility.freeMemory(self.proc_handle, self.code_cave)
            return False
    
    def disable(self):
        """Disable god mode by restoring original bytes"""
        if not self.enabled:
            return
        
        # Restore original bytes
        if self.original_bytes and self.god_mode_addr:
            utility.patchBytes(self.proc_handle, ''.join(f'{b:02x}' for b in self.original_bytes), self.god_mode_addr, len(self.original_bytes))
        
        # Free allocated memory
        if self.code_cave:
            utility.freeMemory(self.proc_handle, self.code_cave)
            self.code_cave = None
        
        self.enabled = False
        print("God mode disabled!")
