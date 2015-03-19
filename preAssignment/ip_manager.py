#!/usr/bin/env python

import csv
import struct
import socket

"""Class that represents a CIDR address."""
class Address(object):

    __slots__ = ('addr', 'note', 'value', 'prefix', 'cidr')

    def __init__(self, addr, note=''):
        self.addr = addr
        self.note = note

        if '/' in addr:
            value, prefix = addr.split('/', 1)
        else:
            value, prefix = addr, '32'
        self.cidr = value + '/' + prefix
        value = self._normalize_addr(value)
        self.value = struct.unpack('>I', socket.inet_aton(value))[0]
        self.prefix = int(prefix)

    def __str__(self):
        return ("<Address(addr='%s', prefix='%s', note='%s')>"
                % (self.addr, self.prefix, self.note))

    def __contains__(self, other):
        if not isinstance(other, Address):
            return False

        self_net = self.value >> (32 - self.prefix)
        other_net = other.value >> (32 - self.prefix)
        return self_net == other_net and self.prefix <= other.prefix

    def _normalize_addr(self, addr):
        tokens = addr.split('.')
        for i in range(4 - len(tokens)):
            tokens.append('0')
        return '.'.join(tokens)


class IPManager(object):
    """Class to manage IP addresses.

    Host IP: 137.43.4.16
    Host CIDR: 137.43.4.16/32
    Network CIDR: 137.43/16
    """

    def __init__(self, storage_fn='storage.csv'):
        self._storage_fn = storage_fn
        open(self._storage_fn, 'a').close()
        self._storage = self._load_storage()

    def _load_storage(self):
        """Load addresses from the storage."""
        storage = {}
        with open(self._storage_fn, 'rt') as fp:
            for row in csv.reader(fp):
                address, note = row
                storage[address] = Address(address, note)
        return storage

    def insert(self, address, note=''):
        """Insert an address to the storage."""
        if address in self._storage:
            print("Skip insert: Address '%s' already exists." % address)
            return

        try:
            with open(self._storage_fn, 'at') as fp:
                w = csv.writer(fp, quotechar='"', quoting=csv.QUOTE_ALL)
                w.writerow((address, note))
        except Exception as e:
            print(e)
        else:
            self._storage[address] = Address(address, note)

    def lookup(self, address):
        """Lookup a given address in the storage."""
        return self._storage.get(address)

    def addrs_by_cidr(self, cidr):
        """Search for addresses by a given cidr."""
        cidr = Address(cidr)
        return [addr for addr in self._storage.values()
                if addr in cidr]

    def addrs_by_note(self, note):
        """Search for addresses by a given note."""
        return [record for record in self._storage.values()
                if note in record.note]


if __name__ == "__main__":
    # create IPManager
    ip_manager = IPManager()

    # insert addresses
    ip_manager.insert('137.43.4.18', 'host')
    ip_manager.insert('137.43.4.19', 'host')
    ip_manager.insert('137.43.4.20/32', 'host/cidr')
    ip_manager.insert('137.43/16', 'net')

    # lookup addresses
    print("\nLookup addresses:")
    print(ip_manager.lookup('137.43.4.18'))
    print(ip_manager.lookup('137.43/16'))

    # search addresses by network cidr
    print("\nSearch addresses by network CIDR:")
    for addr in ip_manager.addrs_by_cidr('137.43.4/24'):
        print(addr)

    # search addresses by note
    print("\nSearch addresses by note:")
    for addr in ip_manager.addrs_by_note('host'):
        print(addr)
