def swap(s, i, j):
  temp = s[i]
  s[i] = s[j]
  s[j] = temp


def ksa(key, keylength=3):
  s = [0] * 256
  for i in range(0, 256):
    s[i] = i

  j = 0
  for i in range(0, 256):
    j = (j + s[i] + key[i % keylength]) % 256  # for us, keylength is 3
    swap(s, i, j)
    # print(s);

  return s


def arc4(key, ciphertext):
  # print(f"Key: {key} | Ciphertext: {ciphertext}")

  key = bytearray.fromhex(key)
  ciphertext = bytearray.fromhex(ciphertext)
  # print(f"Len: {len(ciphertext)} | {ciphertext[0]}")

  # key-scheduling algorithm: initialize the s array
  s = ksa(key)
  # print(s)
  # pseudo-random generation algorithm: generate byte stream (“pad”) to be xor'd with the ciphertext
  i = 0
  j = 0

  message_length = ciphertext[0]
  # pad = [0] * (message_length + 1)
  plaintext = [0] * (message_length + 1)
  plaintext[0] = message_length
  for k in range(1, message_length + 1):
    i = (i + 1) % 256
    j = (j + s[i]) % 256
    swap(s, i, j)
    pk = s[(s[i] + s[j]) % 256]
    # print(pk);
    plaintext[k] = pk ^ ciphertext[k] 
  # print(s)
  
  # print(s)
  # print(pad)
  print(plaintext);
  decrypted = "".join(chr(char) for char in plaintext[1:])
  print(decrypted)
  return decrypted

def crack(data, calculateLength):
  cipherText = (hex(len(data)//3 + 1)[2:].upper() + " " + data) if calculateLength else data
  print(f"Decrypting: {cipherText} | Len: {int(cipherText[0:2], 16)}")
  for i in range(0, 1677215):
    hexKey = hex(i)[2:].upper().rjust(6, "0")
    print(f"----- {i} [{hexKey}] -----")
    decrypted = arc4(hexKey, cipherText)
    if (decrypted.isascii()):
      print(f"Decrypted: {decrypted} | Key: {hexKey}")
      break

def parseCipher(data): 
  cipherText = (hex(len(data)//3 + 1)[2:].upper() + " " + data)
  print(f"Parsed: {cipherText} | Len: {int(cipherText[0:2], 16)}")

# parseCipher("B9 08 68 BB C2 B3 62 F5 2D 16 05 8D C3 78 23 41 76 9A A0 0C 73 6C FB A1 B4 BF 7D 42 9E DE 12 46 84 61 3C 9B 61 32 CC DD 83 E4 79 0C B9 03 6B B6 B9 54 8C 2B A7 E8 90 99 12 EC 8D 17 DB A5 7D 56 3E BF 04 38 DC D8 B5 DD B5 D9 CE EE EB A1 8E B2 6A 26 4F 77 80 F9 AF B8 A8 8B D3 E3 F0 AC AE 5C 6D B5 B6 6B AF 73 14 7B 50 A0 88 A3 23 20 41 B6 83 4E 15 63 A7 27 73 C8 C2")
# parseCipher("B7 20 6B A5 0D 4B 07 2C BD 22 7E CB 0B A3 F1 38 E6 6F E6 47 B7 ED F4 C2 34 E7 B8 FB 05 1B 19 96 4D 61 58 BE 42 04 25 20 F2 3A 63 FA 2C 7B AF 70 46 BA E4 C1 57 0B 70 58 35 C1 D3 39 58 70 9E E2 EC D2 A5 0E 4D 51 9F 37 63 53 9A AD 98 39 64 95 2D 3A A8 43 2F C5 CC 1A C3 90 CA EA A6 FC 24 08")
# parseCipher("EE 09 9D 07 2B C9 28 C5 46 DA EF FF EA F1 C4 60 7D CA EC DA DB 15 77 87 8B 92 13 65 22 48 F0 92 2F EF 30 9C 42 E1 46 62 31 05 6C 43 67 30 4E F6 BF C9 A6 B5 7F F5 B5 6C 6D 48 4E DC 9E B5 FE E5 C9 4B 26 73 FB 86 66 EB FD A3 CB C3 10 6D D9 35 A7 0D 3C 03 85 55 11 D8 82 A7 A2 04 61 76 41 1F 7B D4 EB E7 EB DC 0B C3 3D AA 83 B9 7E D3 CB 22 0D 9C 44 C2 BA 5D 8E 3A 22 16 0D 2D 24 A2")
arc4("9ABBE4", "7E EE 09 9D 07 2B C9 28 C5 46 DA EF FF EA F1 C4 60 7D CA EC DA DB 15 77 87 8B 92 13 65 22 48 F0 92 2F EF 30 9C 42 E1 46 62 31 05 6C 43 67 30 4E F6 BF C9 A6 B5 7F F5 B5 6C 6D 48 4E DC 9E B5 FE E5 C9 4B 26 73 FB 86 66 EB FD A3 CB C3 10 6D D9 35 A7 0D 3C 03 85 55 11 D8 82 A7 A2 04 61 76 41 1F 7B D4 EB E7 EB DC 0B C3 3D AA 83 B9 7E D3 CB 22 0D 9C 44 C2 BA 5D 8E 3A 22 16 0D 2D 24 A2")
# arc4("00033C", "02 01 02")
# ksa(bytearray.fromhex("00033C"))
# Append length to the beginning
# Valid
# arc4(
#   "1E4600",
#   "49 A7 FD 08 01 84 45 68 85 82 5C 85 97 43 4D E7 07 25 0F 9A EC C2 6A 4E A7 49 E0 EB 71 BC AC C7 D7 57 E9 E2 B1 1B 09 52 33 92 C1 B7 E8 4C A1 D8 57 2F FA B8 72 B9 3A FC 01 C3 E5 18 32 DF BB 06 32 2E 4A 01 63 10 10 16 B5 D8"
# )
# Valid
# arc4(
#   "000018",
#   "35 56 C1 D4 8C 33 C5 52 01 04 DE CF 12 22 51 FF 1B 36 81 C7 FD C4 F2 88 5E 16 9A B5 D3 15 F3 24 7E 4A 8A 2C B9 43 18 2C B5 91 7A E7 43 0D 27 F6 8E F9 18 79 70 91"
# )
# arc4(
#   "00033C",
#   "35 56 C1 D4 8C 33 C5 52 01 04 DE CF 12 22 51 FF 1B 36 81 C7 FD C4 F2 88 5E 16 9A B5 D3 15 F3 24 7E 4A 8A 2C B9 43 18 2C B5 91 7A E7 43 0D 27 F6 8E F9 18 79 70 91"
# )
# arc4(
#   "1E4600",
#   '49 A7 FD 08 01 84 45 68 85 82 5C 85 97 43 4D E7 07 25 0F 9A EC C2 6A 4E A7 49 E0 EB 71 BC AC C7 D7 57 E9 E2 B1 1B 09 52 33 92 C1 B7 E8 4C A1 D8 57 2F FA B8 72 B9 3A FC 01 C3 E5 18 32 DF BB 06 32 2E 4A 01 63 10 10 16 B5 D8'
# )

# arc4(hex(24)[2:].upper().rjust(6, "0"), "35 56 C1 D4 8C 33 C5 52 01 04 DE CF 12 22 51 FF 1B 36 81 C7 FD C4 F2 88 5E 16 9A B5 D3 15 F3 24 7E 4A 8A 2C B9 43 18 2C B5 91 7A E7 43 0D 27 F6 8E F9 18 79 70 91");

# Crack ciphertext
# crack("35 56 C1 D4 8C 33 C5 52 01 04 DE CF 12 22 51 FF 1B 36 81 C7 FD C4 F2 88 5E 16 9A B5 D3 15 F3 24 7E 4A 8A 2C B9 43 18 2C B5 91 7A E7 43 0D 27 F6 8E F9 18 79 70 91", False)
# crack("56 C1 D4 8C 33 C5 52 01 04 DE CF 12 22 51 FF 1B 36 81 C7 FD C4 F2 88 5E 16 9A B5 D3 15 F3 24 7E 4A 8A 2C B9 43 18 2C B5 91 7A E7 43 0D 27 F6 8E F9 18 79 70 91", True)
# crack("A7 FD 08 01 84 45 68 85 82 5C 85 97 43 4D E7 07 25 0F 9A EC C2 6A 4E A7 49 E0 EB 71 BC AC C7 D7 57 E9 E2 B1 1B 09 52 33 92 C1 B7 E8 4C A1 D8 57 2F FA B8 72 B9 3A FC 01 C3 E5 18 32 DF BB 06 32 2E 4A 01 63 10 10 16 B5 D8", True)
# crack('4D 21 74 1A E2 D6 91 12 F3 BA 6B 95 D1 E3 68 5A 9E 7A 60 A7 87 01 54 64 20 DD 84 9A A2 A9 B8 A0 4B 86 30 1D A6 65 E0 4A F7 A6 54 D6 43', True)
# crack('83 7B 02 41 0F 0E C8 35 A4 EB 87 00 0F A7 DB 4E 28 1A 0C 30 CD 95 32 DF 3B 96 58 7D 70 29 2A 0B 69 BF E9 53 61 F0 73 6C E1 C2 94 D2 31 8E 34 40 6F AF 52 53 2D 95 20 28 60 D1 DB A6 1C 87 E1 83 BD 81 A6 25 FB A2 93 A8 E6 F4 AD 20', True)
# crack('A7 FD 08 01 84 45 68 85 82 5C 85 97 43 4D E7 07 25 0F 9A EC C2 6A 4E A7 49 E0 EB 71 BC AC C7 D7 57 E9 E2 B1 1B 09 52 33 92 C1 B7 E8 4C A1 D8 57 2F FA B8 72 B9 3A FC 01 C3 E5 18 32 DF BB 06 32 2E 4A 01 63 10 10 16 B5 D8', True)
# crack('56 C1 D4 8C 33 C5 52 01 04 DE CF 12 22 51 FF 1B 36 81 C7 FD C4 F2 88 5E 16 9A B5 D3 15 F3 24 7E 4A 8A 2C B9 43 18 2C B5 91 7A E7 43 0D 27 F6 8E F9 18 79 70 91', True)
# crack('63 39 06 0F EA 3E F5 FB A8 A1 8C 94 62 4D 37 30 20 2B 75 79 88 03 F5 2A 09 54 F2 8E 30 B0 4E 18 24 5E 71 B4 89 40 66 62 CA C4 68 CB DD B1 6F 58 A3 37 13 9A 15 99 57 52 9E 02 B7 39 41 F4 5B 2B 73 70 8C 78 11 0C F2 96 BC 7D EC CE', True)