Script converts CISCO IOS Access Lists (ACL) from its config file to security policies in CSV format

The script takes and argument of a file (-f/--file) that hols ! in its configuration content - typical IOS format.
Script extracts security policies from the configuration file into CVS format file with fields separated by ';'.

 
TODO:
1. NAT policies
2. conversion of hosts to /32
3. conversion of masks into prefixes
4. converrsion of objects into actuall ports or addresses
5. handle remark and add content of it to the description field
