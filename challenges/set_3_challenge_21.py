import sys
sys.set_int_max_str_digits(200000) 

def get_lowest_bits(n, number_of_bits):
    """Returns the lowest "number_of_bits" bits of n."""
    mask = (1 << number_of_bits) - 1
    return n & mask

class MT19937:

    # MT19937 requires an array of size 'n', with each value being 'w' bits
    _n = 624     # Degree of recurrence                  
    _m = 397     # middle word, offset for reference relation defining x, 1 <= m < n
    _w = 32      # word size (number of bits)
    _r = 31      # separation point of one word, 0 <= r <= (w - 1)

    _UMASK = get_lowest_bits((0xffffffff << _r), _w)
    _LMASK = (0xffffffff >> (_w - _r))

    _a = 0x9908b0df              # Decimal - 2567483615

    _u = 11
    _s = 7
    _t = 15
    _l = 18
    _b = 0x9D2C5680              # Decimal - 2636928640
    _c = 0xEFC60000              # Decimal - 4022730752
    _f = 1812433253              # Hex - 0x6c078965

    def __init__(self, seed):
        self.state_array = []

        self.state_array.append(seed)

        for i in range (1, self._n):
            seed = get_lowest_bits(self._f * (seed ^ (seed >> (self._w - 2))) + i, self._w)
            self.state_array.append(get_lowest_bits(seed, self._w))

        self.state_index = 0

    def rand(self):
        k = self.state_index

        j = k - (self._n-1)

        if j < 0: 
            j += self._n

        x = get_lowest_bits((self.state_array[k] & self._UMASK) | (self.state_array[j] & self._LMASK), self._w)

        xA = get_lowest_bits(x >> 1, self._w)

        j = k - (self._n - self._m)

        if j < 0:
            j += self._n

        x = get_lowest_bits(self.state_array[j] ^ xA, self._w)

        k += 1

        self.state_array[k] = x

        if k >= self._n:
            k = 0

        self.state_index = k

        y = get_lowest_bits(x ^ (x >> self._u), self._w) 

        y = get_lowest_bits(y ^ ((y << self._s) & self._b), self._w) 

        y = get_lowest_bits(y ^ ((y << self._t) & self._c), self._w) 

        z = get_lowest_bits(y ^ (y >> self._l), self._w) 

        return get_lowest_bits(z, self._w)


def main():
    for i in range(10):
        print(MT19937(i).rand())


if __name__ == '__main__':
    main()

