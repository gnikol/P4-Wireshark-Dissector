-- Auto-generated dissector from P4 header

-- Helper functions

-- Return a slice of a table
function table_slice(input_table, first, last)
  local subtable = {}
  for i = first, last do
    subtable[#subtable + 1] = input_table[i]
  end
  return subtable
end

-- Convert a number to bits
function tobits(number, bitcount, first_bit, last_bit)
    local bit_table = {}
    for bit_index = bitcount, 1, -1 do
        remainder = math.fmod(number, 2)
        bit_table[bit_index] = remainder
        number = (number - remainder) / 2
    end
    return table.concat(table_slice(bit_table, first_bit, last_bit))
end

-- Convert a buffer into its hexadecimal representation
function tohex(input_buffer, bytecount,  first_bit, last_bit)
    return bit.tobit(input_buffer)
end
