import random
import time
import set_3_challenge_21 as challenge_21

# Instead of waiting for random.randint(40, 1000) seconds as per the challenge, the passage of time is being mimiced.
current_time = int(time.time())

def routine():
    
    global current_time

    current_time += random.randint(40, 1000)

    seed = current_time
    
    prng = challenge_21.MT19937(seed)
    
    current_time += random.randint(40, 1000)
    
    return seed, prng.rand()


def crack_mt19937_seed(prng_output):

    global current_time

    # Start from the current timestamp.
    guessed_seed = current_time

    prng = challenge_21.MT19937(guessed_seed)

    # Decrement the guessed seed by 1 till the random value generated is equal to the provided random value. If the 
    # values are equal, the current guess is the seed.
    while prng.rand() != prng_output:
        guessed_seed -= 1
        prng = challenge_21.MT19937(guessed_seed)

    return guessed_seed
    

if __name__ == '__main__':

    seed, prng_output = routine()

    guessed_seed = crack_mt19937_seed(prng_output)

    assert seed == guessed_seed
    