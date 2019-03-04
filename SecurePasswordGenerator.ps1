<#
    .SYNOPSIS
        SecurePasswordGenerator - Generates somewhat-rememberable passwords probably better than most of the shit you'll come up with. 

    .DESCRIPTION
        Generates somewhat-rememberable passwords probably better than most of the shit you'll come up with. Something, something 
        "Horse Battery Staple". Also guarantees the possibility that someone could re-generate your password, given enough time and 
        effort (if you suck and they somehow know you used this script, and what lists of words and nouns you used, and what options you 
        specified). Overall, this was written to generate passwords that could not be easily bruteforced/cracked, without prior knowledge 
        of the means of production, and could also be memorized with a bit of effort.

    .PARAMETER SameFirstLetter
        Requires that the first letter of each intermediate word be the same. Disabled, by default. Selects the first letter of the first
        intermediate word selected; usually from the NounList, but can be from the WordList if SkipNoun is specified.
        WARNING: This may make remembering easier, but drastically reduces entropy and the overall key space!
        
    .PARAMETER UnCapitalizeFirstLetter
        By default, the first letter of each intermediate word is capitalized. Specify this switch to disable this.
        WARNING: Disabling this could reduce alphabet entropy because these are the only characters that will end up capitalized.
        
    .PARAMETER MinimumWordLength
        Minimum length of each intermediate word used to build the final password candidate. Applies to both word and noun lists.
        WARNING: The higher this value is set, the fewer intermediate words there will be; lowering the overall key space.

    .PARAMETER NumberOfEndCaps
        Number of special characters to append and prepend on to the final password candidate.
        (e.g. a value of 2 could produce {!super_secret_password!}, with the end caps being {} and !!)

    .PARAMETER LeetConversions
        Number of 1337 conversions to perform on the final password candidate. This is the number of unique characters to replace.
        All instances of the randomly selected character, upper and lower case, will be replaced by a suitable l337 character.
        WARNING: This can lower entropy in cases where upper and lower case characters are both replaced with the same 1337 character.

    .PARAMETER NumberOfWords
        Number of intermediate words to build the final password candidate with. The first word comes from the supplied list of Nouns.
        All other Words are randomly selected from the WordList.

    .PARAMETER LeetConversionByOccurrence
        Converts the most frequently occurring characters to 1337 values, instead of randomly selecting them. Disabled, by default.
        WARNING: Lowers entropy through deterministic means.
        
    .PARAMETER SkipNoun
        Skip picking a noun from a separate list of nouns. This essentially just sets the noun value to another word from the word list.
        WARNING: I don't supply a Noun list, which is the only thing differentiating passwords I create and those you create.
        Not using a separate list of Nouns and only the supplied word list will destroy your global uniqueness.

    .PARAMETER WithoutReplacement
        After a word is picked from a list, it is removed from the list so it cannot be picked again. Lowers the overall key space
        possible, but will probably increase entropy. Chances of getting duplicate words in a password is dependent on the size of the 
        supplied word lists.

    .PARAMETER UseSameEndcap
        Picks one random Endcap and uses it the specified NumberOfEndCaps times, instead of picking a new one for each NumberOfEndCaps.
        WARNING: Further reduces final password entropy.

    .PARAMETER PrintEntropy
        Prints out a rough estimate of the generated password candidate's entropy. Also prints the password. This prints two different
        values: relative and perceived entropy. The "perceived" entropy is a measurement of the key space present in the generated password
        candidate; it represents what sheer bruteforcing would need to overcome. The "relative" entropy is a measure relative to the 
        possible combinations this script could produce, given the supplied flags and lists. Each argument modifies the key space of the
        positional words and symbols used to generate the password. This is essentially the entropy given the person cracking your password
        knows you used this script to generate it. My calculations of relative entropy may be a bit off (assumptions were made), though
        they're probably good enough.

    .PARAMETER WordListPath
        Path to a large list of generic words.The supplied file (eff_large_wordlist.txt) is a large list of less-common words, that are 
        still memorable (according to the EFF). I think I filtered out short words, maybe something else... I don't remember. Use something 
        else if you don't like it, don't trust, or want more entropy. This file serves as the main body of entropy from which intermediate 
        words are randomly chosen. From the perspective of cracking, this list functions as your alphabet - the more characters, the larger
        the key space.

    .PARAMETER NounListPath
        Path to a smaller list of more unique/different words. The first intermediate word is always selected from this list. This list 
        supplies additional words, that may or may not be in the large EFF list, to distinguish one person's use over the next.
        
        Cracking without knowing the words that make up this custom alphabet, even if the cracker knows this script and word list were 
        used, creates a situation where the cracker either needs to find a list of nouns containing your nouns or bruteforce the whole
        length of your nouns. This is why it is suggested that you create your own list of large, unique words. These also don't need to be
        literal nouns; they can be anything.

    .PARAMETER WordList
        An array of words to use, instead of reading them from a file. Will significantly limit possibilities to whatever you supply;
        Should only be used for very specific testing purposes. Will be overwritten with the contents of WordListPath, if it is supplied 
        and exists.

    .PARAMETER NounList
        An array of nouns to use, instead of reading them from a file. Will significantly limit possibilities to whatever you supply;
        Should only be used for very specific testing purposes. Will be overwritten with the contents of NounListPath, if it is supplied 
        and exists.

    .EXAMPLE
        > SecurePasswordGenerator
          =Complex Craf+y Immunize Gu+less=

    .EXAMPLE
        > SecurePasswordGenerator
          *Dama9e Tannin9 Aspire Precise*

    .EXAMPLE
        Specifying SameFirstLetter with default settings:
        
        > SecurePasswordGenerator -SameFirstLetter
          !Midnigh+ Mushily Moonwalk Mooing!
          
    .EXAMPLE
        > SecurePasswordGenerator -SameFirstLetter -LeetConversions 1 -LeetConversionByOccurrence -NumberOfWords 8
          _Worry_Wr3cking_Wr3cking_Winking_Wr3ath_Wid3n_Washhous3_Wrath_

    .EXAMPLE
        Same as the last, but without replacement:
        
        > SecurePasswordGenerator -SameFirstLetter -LeetConversions 1 -LeetConversionByOccurrence -NumberOfWords 8 -WithoutReplacement
          ^F4ult F4ci4l Fervor F4csimile Fr4ction Finishing F4nt4sy F4vor4ble^

    .EXAMPLE
        Something more secure:
        
        > SecurePasswordGenerator -LeetConversions 2 -NumberOfWords 5
          _Funer&l Ve9&n Issue Unlovin9 Ri9or_


    .NOTES
        The ideas behind this script are based off of the EFF post in the LINK section. This is sort of what they suggested doing,
        though they probably realised that actually implementing what they were describing would create more problems and struggle
        than simply telling people what to do; thoughts and ideas over implementation - another reason why the EFF sucks.
        So here's my poor implementation of a Horse-Battery-Staple generator.

        I'm no mathematician but, if you use the supplied eff_large_wordlist.txt, the default flags, and my calculations are correct, 
        I believe the upper bound of possible combinations is something like:
            586,000,000,000,000 * X
            
        Where X is the number of nouns in your supplied NounListPath. Let's assume you find a list of ~800 unique nouns you like,
        we have a modified hashcat using this script's optimized logic and word/nount lists as an alphabet, and we're cracking hashes 
        at a decent 4GH/s, it would take about 1,300 days to fully exhaust the key space. This is comparable to having a random 9 
        character string (95 ^ 9) bruteforced, though without standard bruteforcing being possible. Of course, this is the upper bound,
        without any other flags specified that might reduce total possible combinations, and is also based on some shitty, barely-
        thought-out maths.

        The EXAMPLEs I have included were all generated with a very weak NounList, with a lot of smaller words.

    .LINK
        https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases

#>
function SecurePasswordGenerator
{
    param (
        [Switch] $SameFirstLetter = $false,
        [Switch] $UnCapitalizeFirstLetter = $false,
        [int] $MinimumWordLength = 4,
        [int] $NumberOfEndCaps = 1,
        [int] $LeetConversions = 1,
        [int] $NumberOfWords = 4,
        [Switch] $LeetConversionByOccurrence = $false,
        [Switch] $SkipNoun = $false,
        [Switch] $WithoutReplacement = $false,
        [Switch] $UseSameEndcap = $false,
        [Switch] $PrintEntropy = $false,
        [string] $WordListPath = ".\eff_large_wordlist.txt",
        [string] $NounListPath = ".\path_to_your_noun_list.txt",
        [Object[]] $WordList = @(),
        [Object[]] $NounList = @()
    )
    
    $BitsOfEntropy = 1

    # Not all vowels, but that's what I'm calling them...
    # Letters and what they can bee 13373d into.
    $LeetVowels = @{
        "a" = @("@","4","&")
        "b" = @("6","8")
        "c" = @("{","(","[","<")
        "e" = @("3")
        "g" = @("9")
        "h" = @("#")
        "i" = @("1","|","!")
        "l" = @("|","!","1")
        "o" = @("0")
        "q" = @("9")
        "s" = @("$","5")
        "t" = @("+","7")
        "x" = @("%")
        "z" = @("2")
    }

    # Characters that can encapsulate the final password.
    $EndCaps = @(
        @("{", "}"),
        @("(", ")"),
        @("[", "]"),
        @("<", ">"),
        @("~", "~"),
        @("!", "!"),
        @("@", "@"),
        @("#", "#"),
        @("$", "$"),
        @("%", "%"),
        @("^", "^"),
        @("&", "&"),
        @("*", "*"),
        @("-", "-"),
        @("_", "_"),
        @("+", "+"),
        @("=", "="),
        @("|", "|"),
        @(":", ":"),
        @(";", ";"),
        @("`"", "`""),
        @("'", "'"),
        @("?", "?"),
        @(".", "."),
        @(",", ",")
    )

    # Characters base words can be joined with.
    $Joiners = @(
        " ",
        "_"
    )

    # If no word list path or list of words is supplied, error and return null.
    if([string]::IsNullOrWhiteSpace($WordListPath) -and ($WordList -eq $null -or $WordList.Count -eq 0))
    {
        "[!] No list of words or word list path supplied." | Write-Warning
        return $null
    }

    # If a valid path to an existing list of words is supplied, read it in; Else, error and return null.
    if(![string]::IsNullOrWhiteSpace($WordListPath))
    {
        if(Test-Path $WordListPath -PathType Leaf)
        {
            try
            {
                # Filter out any empty lines and lines less than the minimum length, and set everything to lowercase.
                $WordList = @()
                Get-Content $WordListPath | Where {![string]::IsNullOrWhiteSpace($_) -and $_.Length -gt $MinimumWordLength} | % {$WordList += $_.ToLower()}
            }
            catch
            {
                "[!] Could not open supplied word list: {0}" -F $WordListPath | Write-Warning
                return $null
            }
        }
        else
        {
            "[!] Supplied word list does not exist: {0}" -F $WordListPath | Write-Warning
            return $null
        }
    }

    # If we make it here and somehow don't have enough words: error and return null.
    if($WordList -eq $null -or $WordList.Count -eq 0 -or $WordList.Count -lt $NumberOfWords)
    {
        "[!] Not enough suitable words to work with." | Write-Warning
        return $null
    }

    # If no noun list path or list of nouns is supplied, error and return null.
    if([string]::IsNullOrWhiteSpace($NounListPath) -and ($NounList -eq $null -or $NounList.Count -eq 0))
    {
        "[!] No list of nouns or noun list path supplied." | Write-Warning
        return $null
    }
    if($SkipNoun -eq $false)
    {
        # If a valid path to an existing list of nouns is supplied, read it in; Else, error and return null.
        if(![string]::IsNullOrWhiteSpace($NounListPath))
        {
            if(Test-Path $NounListPath -PathType Leaf)
            {
                try
                {
                    # Filter out any empty lines and lines less than the minimum length, and set everything to lowercase.
                    $NounList = @()
                    Get-Content $NounListPath | Where {![string]::IsNullOrWhiteSpace($_) -and $_.Length -gt $MinimumWordLength} | % {$NounList += $_.ToLower()}
                }
                catch
                {
                    "[!] Could not open supplied noun list: {0}" -F $NounListPath | Write-Warning
                    return $null
                }
            }
            else
            {
                "[!] Supplied noun list does not exist: {0}" -F $NounListPath | Write-Warning
                return $null
            }
        }

        # If we make it here and somehow don't have any nouns: error and return null.
        if($NounList -eq $null -or $NounList.Count -eq 0)
        {
            "[!] No suitable nouns to work with." | Write-Warning
            return $null
        }
    }

    # Get a random Joiner.
    $Joiner = Get-Random -InputObject $Joiners

    # I believe the multiple Joiners in the final password will act as one pool; only one joiner is selected.
    $BitsOfEntropy += [Math]::Log(($Joiners.Count), 2)

    # Get a random Noun.
    if($SkipNoun)
    {
        # If skipping selecting nouns from the NounList, select one from the WordList.
        $Noun = Get-Random -InputObject $WordList -Count 1
        
        # Add the bits of entropy from selecting from the WordList.
        $BitsOfEntropy += [Math]::Log(($WordList.Count), 2)

        # Remove selected value from the greater pool of values if replacement is disabled.
        if($WithoutReplacement)
        {
            $WordList = ($WordList | Where {$_ -ne $Noun})
        }
    }
    else
    {
        # Else, get a random Noun from the NounList.
        $Noun = Get-Random -InputObject $NounList -Count 1

        # Add the bits of entropy from selecting from the NounList.
        $BitsOfEntropy += [Math]::Log(($NounList.Count), 2)

        # Remove selected value from the greater pool of values if replacement is disabled.
        if($WithoutReplacement)
        {
            $NounList = ($NounList | Where {$_ -ne $Noun})
        }
    }
    
    # Filter words down to those starting with the first letter of the Noun, if specified.
    if($SameFirstLetter -eq $true)
    {
        $WordList = ($WordList | Where-Object {$_.StartsWith($Noun[0], $true, $null)})
    }

    # If we make it here and somehow don't have enough words: error and return null.
    if($WordList -eq $null -or $WordList.Count -eq 0 -or $WordList.Count -lt ($NumberOfWords - 1))
    {
        "[!] Not enough suitable words to work with." | Write-Warning
        return $null
    }

    # Capitalize first letter if the UnCapitalizeFirstLetter is NOT set.
    if($UnCapitalizeFirstLetter -eq $false)
    {
        $Noun = (Get-Culture).TextInfo.ToTitleCase($Noun)
    }
    
    # The list of base words that will be joined together to create the final password.
    $BaseWords = @($Noun)
    
    # Base Word Selection Phase.
    for([int] $index = 0; $index -lt ($NumberOfWords - 1); $index++)
    {
        # Select a random word from the WordList.
        $NewWord = Get-Random -InputObject $WordList -Count 1

        # Add the bits of entropy from selecting from the WordList.
        $BitsOfEntropy += [Math]::Log(($WordList.Count), 2)

        # Remove selected value from the greater pool of values if replacement is disabled.
        if($WithoutReplacement)
        {
            $WordList = ($WordList | Where {$_ -ne $NewWord})
        }

        # Capitalize first letter if the UnCapitalizeFirstLetter is NOT set.
        if($UnCapitalizeFirstLetter -eq $false)
        {
            $NewWord = (Get-Culture).TextInfo.ToTitleCase($NewWord)
        }

        $BaseWords += $NewWord
    }

    # Join all the base words using the selected Joiner.
    $BasePassword = [string]::Join($Joiner, $BaseWords)

    # Get all possible 1337 conversions and their frequencies.
    $PossibleLeetConversion = @{}
    $BasePassword.ToCharArray() | % {
        if($LeetVowels.ContainsKey($_.ToString().ToLower()))
        {
            if(!$PossibleLeetConversion.ContainsKey($_.ToString().ToLower()))
            {
                $PossibleLeetConversion[$_.ToString().ToLower()] = 0
            }
            $PossibleLeetConversion[$_.ToString().ToLower()] += 1
        }
    }

    # Check if there are enough possible 1337 conversions available to continue.
    if($PossibleLeetConversion.Count -lt $LeetConversions)
    {
        "[!] Not enough possible 1337 conversions to meet desired total: {0}/{1}" -F $PossibleLeetConversion.Count, $LeetConversions | Write-Warning
        return $null
    }

    # 1337 Conversion Phase.
    for([int] $index = 0; $index -lt $LeetConversions; $index++)
    {
        $VowelToReplace = ""
        $ReplacementValue = ""

        if($LeetConversionByOccurrence -eq $true)
        {
            # Select the most frequently occurring character, that can be replaced with a 1337 value, to replace.
            $VowelToReplace = $PossibleLeetConversion.GetEnumerator() | Sort -Property Value -Descending | Select -First 1 -ExpandProperty Name
            
            # If the 1337 replacement contains multiple possibilities, choose a random one to use.
            $ReplacementValue = Get-Random -InputObject ($LeetVowels[$VowelToReplace]) -Count 1

            # We are selecting from a pool of the total possible 1337 replacements for a determined value. The VowelToReplace is deterministc, 
            # so I don't think we can count the pool of all LeetVowels or count the character being replaced.
            # I think the replacement of all upper and lower case instances is also deterministic and shouldn't count more than once.
            $BitsOfEntropy += [Math]::Log(($LeetVowels[$VowelToReplace].Count), 2)
        }
        else
        {
            # Else, select a random character, that can be replaced with a 1337 value, to replace.
            $VowelToReplace = Get-Random -InputObject @($PossibleLeetConversion.Keys) -Count 1

            # If the 1337 replacement contains multiple possibilities, choose a random one to use.
            $ReplacementValue = Get-Random -InputObject ($LeetVowels[$VowelToReplace]) -Count 1

            # We are selecting from a pool of all replaceable characters, with multiple replacements for each character.
            # The size of this pool is determined by the number of possible 1337 conversions.
            # Each time 1337 characters are replaced, they are essentially removed from the replaceable pool.
            $BitsOfEntropy += [Math]::Log(($PossibleLeetConversion.Keys | % {$LeetVowels[$_].Count} | Measure-Object -Sum | Select -ExpandProperty Sum), 2)
        }

        # Replace both the upper and lower case character with this value.
        $BasePassword = $BasePassword.Replace($VowelToReplace.ToLower(), $ReplacementValue)
        $BasePassword = $BasePassword.Replace($VowelToReplace.ToUpper(), $ReplacementValue)
        $PossibleLeetConversion.Remove($VowelToReplace.ToLower())

        # I'm considering each replacement of a 1337able character as adding one letter to the final password, as far as entropy matters.
    }

    # Endcap Phase.
    # Pick the first Endcap to use for each Endcap if UseSameEndcap is specified.
    $EndCap = Get-Random $EndCaps

    if($UseSameEndcap)
    {
        # I'm considering each addition of two endcaps to be one additional letter on the final password, as far as entropy matters,
        # because adding one to one side determines if the corresponding one will be added to the other.
        # This will only add the entropy of the EndCaps pool once.
        $BitsOfEntropy += [Math]::Log(($EndCaps.Count), 2)
    }

    for([int] $index = 0; $index -lt $NumberOfEndCaps; $index++)
    {
        
        if($UseSameEndcap)
        {
            # Do not select a new Endcap if the UseSameEndcap value was specified.
            if($index -gt 0)
            {
                # Though we are not selecting from the EndCaps pool on subsequent passes, we are essentially selecting from a pool of no new
                # endcap and the same endcap again - two possible outcomes.
                $BitsOfEntropy += [Math]::Log(($EndCaps.Count), 2)
            }
        }
        else
        {
            # Else, if not using the same Endcap each time, randomly select a new one.
            $EndCap = Get-Random $EndCaps

            # I'm considering each addition of two endcaps to be one additional letter on the final password, as far as entropy matters,
            # because adding one to one side determines if the corresponding one will be added to the other.
            # This will add entropy for each iteration, given a random endcap is selected each time.
            $BitsOfEntropy += [Math]::Log(($EndCaps.Count), 2)
        }

        # Cap it.
        $BasePassword = "{0}{1}{2}" -F ($EndCap[0]), $BasePassword, ($EndCap[1])
    }

    if($PrintEntropy)
    {
        $LowerRe = [System.Text.RegularExpressions.Regex]::new("[a-z]")
        $UpperRe = [System.Text.RegularExpressions.Regex]::new("[A-Z]")
        $DigitRe = [System.Text.RegularExpressions.Regex]::new("[0-9]")
        $OtherRe = [System.Text.RegularExpressions.Regex]::new("[^0-9a-zA-Z]")
        $PoolPerCharacter = 0

        if($LowerRe.IsMatch($BasePassword)) { $PoolPerCharacter += 26 }
        if($UpperRe.IsMatch($BasePassword)) { $PoolPerCharacter += 26 }
        if($DigitRe.IsMatch($BasePassword)) { $PoolPerCharacter += 10 }
        if($OtherRe.IsMatch($BasePassword)) { $PoolPerCharacter += 23 }

        $PerceivedEntropy = ([Math]::Log($PoolPerCharacter, 2) * $BasePassword.Length)

        "Relative Entropy:   {0}" -F $BitsOfEntropy | Write-Host
        "Perceived Entropy:  {0}" -F $PerceivedEntropy | Write-Host
        "Password Candidate: {0}" -F $BasePassword | Write-Host
        Write-Host
    }

    return $BasePassword
}
