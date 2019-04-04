#!/usr/bin/env python2

class MACAddress(object):
    """
    Represent and manipulate single MAC Addresses.
    """
    
    def __init__(self, address):

        if isinstance(address, (int, long)):
            self._mac = address
            if address < 0 or address > 2**48-1:
                raise ValueError(address)
            return

        address = str(address)
        self._mac = self._mac_int_from_string(address)

    @staticmethod
    def _mac_int_from_string(address):
        parts = address.split(':')
        if len(parts) != 6:
            raise ValueError(address)
         
        packed_mac = 0
        for p in parts:
            packed_mac = (packed_mac << 8) | int(p, 16)
                
        return packed_mac

    @staticmethod
    def _mac_string_from_int(address):
        octets = []
        for _ in xrange(6):
            octets.insert(0, hex(address & 0xFF)[2:].rjust(2, '0'))
            address >>= 8
        return ':'.join(octets)

    def __int__(self):
        return self._mac

    def __hex__(self):
        return hex(self._mac)
    
    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, str(self))

    def __str__(self):
        return '%s' % self._mac_string_from_int(self._mac)

    def __lt__(self, other):
        if not isinstance(other, MACAddress):
            raise TypeError('%s and %s are not of the same type' % (
                    str(self), str(other)))
        if self._mac != other._mac:
            return self._mac < other._mac
        return False

    def __gt__(self, other):
        if not isinstance(other, MACAddress):
            raise TypeError('%s and %s are not of the same type' % (
                    str(self), str(other)))
        if self._mac != other._mac:
            return self._mac > other._mac
        return False

    
    def __eq__(self, other):
        try:
            return (self._mac == other._mac)
        except AttributeError:
            return NotImplemented
    
    def __ne__(self, other):
        eq = self.__eq__(other)
        if eq is NotImplemented:
            return NotImplemented
        return not eq

    def __add__(self, other):
        if not isinstance(other, int):
            return NotImplemented
        return MACAddress(int(self) + other)

    def __sub__(self, other):
        if not isinstance(other, int):
            return NotImplemented
        return MACAddress(int(self) - other)
