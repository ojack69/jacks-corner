#!/usr/bin/env python3

import argparse

def to_binary_representation(raw):
    return ' '.join('{0:08b}'.format(ord(x), 'b') for x in raw)



if __name__ == '__main__':
    parser = argparse.ArgumentParser(
                    prog='XOR Key Calculator',
                    description='Calculate the XOR key for the provided input and expected XOR result')
    parser.add_argument('input')   
    parser.add_argument('expected')
    args = parser.parse_args()
    
    original = args.input.strip()
    expected = args.expected.strip()
    
    xor = {
        "1_0": "1",
        "1_1": "0",
        "0_1": "1",
        "0_0": "0"
    }
    
    if len(original) != len(expected):
        print("Length of input and expected result must match!")
        exit(1)
    
    binary_original = to_binary_representation(original).split(' ')
    binary_expected = to_binary_representation(expected).split(' ')
    result = []
    
    for i in range(0, len(binary_original)):
        binary_1 = binary_original[i]
        binary_2 = binary_expected[i]
        binary_r = ""
    
        for b in range(0, 8):
            binary_r += xor[f"{binary_1[b]}_{binary_2[b]}"]
        
        result.append(binary_r)
    
    print(" ".join([hex(int(x, 2)) for x in result]))
    

