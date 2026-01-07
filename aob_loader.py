import utility

def loadAOB(process, pattern, executible):
    """Utility function to perform AOB scan and return address"""
    addr = utility.aobScan(process, pattern, executible)
    if not addr:
        return None
    return addr