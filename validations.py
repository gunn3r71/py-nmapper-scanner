def validate_ip(ip: str):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if not 0 <= int(part) <= 255:
            return False
    return True

def validate_scan_type(scan_type: str):
    return scan_type != "" and scan_type in ["1", "2", "3"]