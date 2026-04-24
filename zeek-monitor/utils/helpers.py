import ipaddress

def is_internal(ip):

    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False