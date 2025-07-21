import unittest

from src.models import Address

ANY_VALUE = 1


class TestAddress(unittest.TestCase):
    def test_equal_same_value(self):
        first_address = Address(ANY_VALUE)
        second_address = Address(ANY_VALUE)

        self.assertEqual(first_address, second_address)

    def test_equal_different_value(self):
        first_address = Address(ANY_VALUE)
        second_address = Address(ANY_VALUE + 1)

        self.assertNotEqual(first_address, second_address)

    def test_equal_different_objects(self):
        first_address = Address(ANY_VALUE)
        second_address = "not an address"

        self.assertNotEqual(first_address, second_address)
