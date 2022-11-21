import set_1_challenge_3 as challenge_3

file = open("./challenges/files/4.txt", "r")
lines = file.readlines()

scores = {}
keys = {}
results = {}

for counter, line in enumerate(lines):
	

	key, plaintext, score = challenge_3.detect_xor_key(line.strip())

	scores[counter] = score
	keys[counter] = key
	results[counter] = plaintext

sorted_scores = dict(sorted(scores.items(), key=lambda item: item[1])[:1])

for key in sorted_scores.keys():
	print("Line " + str(key+1) + ": " + results[key])


