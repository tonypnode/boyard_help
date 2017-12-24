

def get_cmdb_data(device_type):
    """
    Get data from observium database based on the device_type

    Should return dictionary of:
    ID, Hostname, OS_Version

    :return: dict
    """
    pass

def psirt_query(image, version):
    """
    Send required information to PSIRT API and return true if vulnerable?

    :return: bool
    """
    pass

def junos_cve_query(version):
    """
    not sure about this one, prolly the same kind of deal as PSIRT, but for Junos

    :return: bool
    """
    pass

def update_vluln_table():
    """
    add Date, CMDB_ID, Hostname, is_vuln=True
    :return:
    """

