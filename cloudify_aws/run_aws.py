# noinspection PySingleQuotedDocstring
"""
Created on 24-Feb-2014
Execution of cloudify_aws provider
@author: Ganesh
"""

#from cloudify_aws import init
from cloudify_aws import bootstrap

#print init("", False, True)
print bootstrap(config_path=None, is_verbose_output=True,
                bootstrap_using_script=True)

#from boto.ec2 import connect_to_region

# conn = connect_to_region(region_name)
#
# conn.get_all_network_interfaces()

