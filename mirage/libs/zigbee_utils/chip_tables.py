'''
This file allows to manipulate Zigbee chips.
'''
SYMBOL_TO_CHIP_MAPPING = [
	{"symbols":"0000", "chip_values":"11011001110000110101001000101110","msk_values":"1100000011101111010111001101100"},
	{"symbols":"1000", "chip_values":"11101101100111000011010100100010","msk_values":"1001110000001110111101011100110"},
	{"symbols":"0100", "chip_values":"00101110110110011100001101010010","msk_values":"0101100111000000111011110101110"},
	{"symbols":"1100", "chip_values":"00100010111011011001110000110101","msk_values":"0100110110011100000011101111010"},
	{"symbols":"0010", "chip_values":"01010010001011101101100111000011","msk_values":"1101110011011001110000001110111"},
	{"symbols":"1010", "chip_values":"00110101001000101110110110011100","msk_values":"0111010111001101100111000000111"},
	{"symbols":"0110", "chip_values":"11000011010100100010111011011001","msk_values":"1110111101011100110110011100000"},
	{"symbols":"1110", "chip_values":"10011100001101010010001011101101","msk_values":"0000111011110101110011011001110"},
	{"symbols":"0001", "chip_values":"10001100100101100000011101111011","msk_values":"0011111100010000101000110010011"},
	{"symbols":"1001", "chip_values":"10111000110010010110000001110111","msk_values":"0110001111110001000010100011001"},
	{"symbols":"0101", "chip_values":"01111011100011001001011000000111","msk_values":"1010011000111111000100001010001"},
	{"symbols":"1101", "chip_values":"01110111101110001100100101100000","msk_values":"1011001001100011111100010000101"},
	{"symbols":"0011", "chip_values":"00000111011110111000110010010110","msk_values":"0010001100100110001111110001000"},
	{"symbols":"1011", "chip_values":"01100000011101111011100011001001","msk_values":"1000101000110010011000111111000"},
	{"symbols":"0111", "chip_values":"10010110000001110111101110001100","msk_values":"0001000010100011001001100011111"},
	{"symbols":"1111", "chip_values":"11001001011000000111011110111000","msk_values":"1111000100001010001100100110001"}
]


def OQPSKtoMSKsymbols(pn,order=["11","01","00","10"]):
	'''
	This function allows to convert a given O-QPSK binary string to its equivalent MSK binary string.

	:param pn: sequence to convert (binary string)
	:type pn: str
	:param order: list of binary string describing the sequence of constellation symbols to use
	:type order: list of str
	:return: MSK binary string corresponding to the provided O-QPSK binary string
	:rtype: str

	.. note::

		This function has been used to generate the SYMBOL_TO_CHIP_MAPPING dictionary.

	'''
	liste = []
	start_symbol = "11"
	index = order.index(start_symbol)
	for i in range(1,len(pn)):
		current = pn[i]
		if i % 2 == 1: # odd
			if order[(index+1)%len(order)][1] == current:
				index = (index + 1) % len(order)
				liste.append("1")
			else:
				index = (index - 1) % len(order)
				liste.append("0")
		else: # even
			if order[(index+1)%len(order)][0] == current:
				index = (index + 1) % len(order)
				liste.append("1")
			else:
				index = (index - 1) % len(order)
				liste.append("0")

	print(order[index])
	return ''.join(liste)


def hamming(sequence1, sequence2):
	'''
	This function returns the hamming distance between two binary string. The two strings must have the same length.

	:param sequence1: first binary string
	:type sequence1: str
	:param sequence2: second binary string
	:type sequence2: str
	:return: hamming distance
	:rtype: int

	'''
	if len(sequence1) == len(sequence2):
		count = 0
		for i in range(len(sequence1)):
			if sequence1[i] != sequence2[i]:
				count += 1
		return count
	else:
		return None

def checkBestMatch(sequence,subtype="msk_values"):
	'''
	This function explores the SYMBOL_TO_CHIP_MAPPING table and returns the best match (i.e. the symbol with the lowest hamming distance) for the provided sequence.

	:param sequence: binary string to analyze
	:type sequence: str
	:param subtype: string indicating if the comparison must be performed using MSK values or OQPSK values ("msk_values" or "chip_values")
	:type subtype: str
	:return: tuple composed of the best symbol and the corresponding hamming distance
	:rtype: (str, int)

	'''
	min_hamming = hamming(sequence,SYMBOL_TO_CHIP_MAPPING[0][subtype])
	best_match = SYMBOL_TO_CHIP_MAPPING[0]["symbols"]
	for i in SYMBOL_TO_CHIP_MAPPING[1:]:
		current = hamming(sequence,i[subtype])
		if current <= min_hamming:
			min_hamming = current
			best_match = i["symbols"]
	return (best_match,min_hamming)
