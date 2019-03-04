# SecurePasswordGenerator
PowerShell script that generates Horse-Battery-Staple style passwords.

Generates somewhat-rememberable passwords probably better than most of the shit you'll come up with. Something, something "Horse Battery Staple". Also guarantees the possibility that someone could re-generate your password, given enough time and effort (if you suck and they somehow know you used this script, and what lists of words and nouns you used, and what options you specified). Overall, this was written to generate passwords that could not be easily bruteforced/cracked, without prior knowledge of the means of production, and could also be memorized with a bit of effort.

# Notes
The ideas behind this script are based off of [this EFF post](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases). This is sort of what they suggested doing, though they probably realised that actually implementing what they were describing would be difficult, create the same problem this script creates (limits the key space), and generates some level of liability over simply telling people what to do; thoughts and ideas over action and implementation. So here's my poor implementation of a Horse-Battery-Staple generator. 

I'm no mathematician but, if you use the supplied eff_large_wordlist.txt, the default flags, and my calculations are correct, I believe the upper bound of possible combinations is something like:
    586,000,000,000,000 * X

Where X is the number of nouns in your supplied NounListPath. Let's assume you find a list of ~800 unique nouns you like, we have a modified hashcat using this script's optimized logic and word/nount lists as an alphabet, and we're cracking hashes at a decent 4GH/s, it would take about 1,300 days to fully exhaust the key space. This is comparable to having a random 9 character string (95 ^ 9) bruteforced, though without standard bruteforcing being possible. Of course, this is the upper bound, without any other flags specified that might reduce total possible combinations, and is also based on some shitty, barely-thought-out maths.

See script for more detailed explanations.
