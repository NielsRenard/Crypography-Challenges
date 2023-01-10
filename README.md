# my solutions

To keep the ball rolling after finishing [Advent of Code](https://adventofcode.com/ "puzzles!!!") 2022, I picked up the cryptopals cryptography challenges.
For theory I mostly got by reading [Crypto101.io](https://www.crypto101.io/). Below is an introductory summary on these challenges.

# cryptopals.com

>"We've built a collection of exercises that demonstrate attacks on real-world crypto."
>
>This is a different way to learn about crypto than taking a class or
>reading a book. We give you problems to solve. They're derived from
>weaknesses in real-world systems and modern cryptographic
>constructions. We give you enough info to learn about the underlying
>crypto concepts yourself. When you're finished, you'll not only have
>learned a good deal about how cryptosystems are built, but you'll also
>understand how they're attacked.


# introduction by Maciej Ceglowski

The Matasano Crypto Challenges

I recently took some time to work through the Matasano crypto challenges, a set of 48 practical programming exercises that Thomas Ptacek and his team at Matasano Security have developed as a kind of teaching tool (and baited hook).

Much of what I know (or think I know) about security has come from reading tptacek's comments on Hacker News, so I was intrigued when I first saw him mention the security challenges a few months ago. At the same time, I worried that I'd be way out of my depth attempting them.

As a programmer, my core strengths have always been knowing how to apologize to users, and composing funny tweets. While I can hook up a web template to a database and make the squigglies come out right, I cannot efficiently sort something for you on a whiteboard, or tell you where to get a monad. From my vantage point, crypto looms as high as Mount Olympus.

To my delight, though, I was able to get through the entire sequence. It took diligence, coffee, and a lot of graph paper, but the problems were tractable. And having completed them, I've become convinced that anyone whose job it is to run a production website should try them, particularly if you have no experience with application security.

Since the challenges aren't really documented anywhere, I wanted to describe what they're like in the hopes of persuading busy people to take the plunge.

You get the challenges in batches of eight by emailing cryptopals at Matasano, and solve them at your own pace, in the programming language of your choice. Once you finish a set, you send in the solutions and Sean unlocks the next eight. (Curiously, after the third set, Gmail started rejecting my tarball as malware.)

Most of the challenges take the form of practical attacks against common vulnerabilities, many of which will be sadly familiar to you from your own web apps. To keep things fun and fair for everyone, they ask you not to post the questions or answers online. (I cleared this post with Thomas to make sure it was spoiler-free.)

The challenges start with some basic string manipulation tasks, but after that they are grouped by theme. In most cases, you first implement something, then break it in several enlightening ways. The constructions you use will be familiar to any web programmer, but this may be the first time you have ever taken off the lid and looked at the moving parts inside.

Here are the cryptographic topics covered:

    basic substitution and XOR
    pseudo-random number generators
    stream and block ciphers, and their modes of operation
    message authentication codes
    Diffie-Hellman key exchange
    RSA (public-key cryptography)

Going into the challenges, I worried that my math wouldn't be up to the task. My impression of Serious Crypto was that it required all kinds of group theory, abstract algebra, elliptic curves, vector spaces, and other scary stuff. But while this may be true, the math content for the practical challenges was much gentler:

    working in base 2 and base 16
    modular arithmetic
    discrete exponentiation
    Hamming distance (& friends)
    primality testing
    basic stats (standard deviation & variance)

While the math concepts weren't hard, getting a real feel for them took work (and this was the point of the exercise).

If you're an experienced programmer, the Matasano challenges are also a terrific excuse to try a new programming language. It's always much more fun to solve real problems than it is to write a Manager object that inherits from Employee.

Here are the language features I found myself using most:

    string manipulation (ranges, substrings)
    bitwise operators
    lookup hashes
    conversion between string and number formats
    big integer operations
    packing and unpacking binary data
    pattern matching
    url manipulation
    client/server interaction over a socket

Altogether it took me about three weeks to do the full cycle, working pretty intensively. Skilled programmers will find the going much faster, especially if you're comfortable with bit twiddling. Very few of the problems were downright hard, though some required several hours of work. I spent most of my time stepping through algorithms in pursuit of bugs, and in the process really got a feel for the moving parts in various cryptographic constructions.

I would compare the experience to having only ever read cookbooks and watched cooking shows, and then being asked to fry an egg. You know exactly what to do... in principle.

Some of the challenges have a payoff, in that you decrypt a short bit of secret text. This is incredibly fun. Seeing a cracked message come up on the screen after an evening of bug chasing reminded me of how it felt to be a kid in front of my Apple ][, finally getting it to beep or draw a circle or print DONGS all over the screen. Some of the later challenges even display the answer 'Hollywood style', where you get to see it decrypt one letter at a time in a cascade of print statements.

While the rules don't stipulate it, I think it's a good idea not to look at anyone's code if you try the challenges. The goal here is to convert message-board levels of understanding into actual knowledge, and the only way that works is if you bang your head on the task without seeing how anyone else has done it. Sean was really helpful in helping me navigate difficult spots, and the challenges are not set up to intentionally trick you. But you will need the kind of graph paper with the small squares.

What surprised me most:

    How practical these attacks were. A lot of stuff that I knew was weak in principle (like re-using a nonce or using a timestamp as a 'random' seed) turns out to be crackable within seconds by an art major writing crappy Python.

    There is no difference, from the attacker's point of view, between gross and tiny errors. Both of them are equally exploitable. In at least three challenges, the mere fact of getting distinguishable error messages was enough to recover the entire message.

    This lesson is very hard to internalize. In the real world, if you build a bookshelf and forget to tighten one of the screws all the way, it does not burn down your house

    Timing attacks are much more effective than I imagined.

    Someone who can muck with your ciphertext is halfway to reading it, possibly with your secret key for dessert.

    Some mistakes are incredibly non-obvious. I had no idea you had to super-carefully pad RSA, for example.

    Even on a laptop, in 10 minutes you can do a terrifying amount of computation. It really is 2013.

I mentioned earlier that I thought every web programmer should try their hand at these. It is very illuminating to look at your own web app from the vantage point of an attacker actually writing code. At the very least, you will never be confused about cipher block modes again, or have to worry that someone will ask you to explain how a public key works in an interview. And there is a whole slew of dumb mistakes you will now avoid (replacing them with smarter mistakes that will become the subject matter of challenges 48-96).

The best part, from a web app developer's perspective, is that you never once write a SQL statement or HTML tag.

Here are some specific lessons from the challenges that I will apply to my own work:

    Keep meaningful data out of tokens (like cookies) that I hand out to clients. Use random values keyed against a database, memory store, or wherever.

    If I have to put data in tokens, include an integrity check, and pay a real crypto person to vet it.

    I must never seed a PRNG with a timestamp. I used to do this with microsecond precision thinking I was being clever. Then I went ahead and wrote a script that guessed the seed value in just a few seconds, and now I will never do that again.

    Use constant-time string comparisons when testing incoming data against some target value for authentication purposes. This is easy enough to do in most languages to make it cheap insurance.

    Anything related to authentication should only fail in one way. I must not provide distinguishable errors to the user.

    If possible, find a way to log the fact that someone is making a lot of weird queries against my site. For extra points, try not to make the logger itself hackable.

    No third-party javascript. I hated it already, now I hate it more.

    Cut off one of my fingers each time I re-use a nonce.

Having read this post, you can go to Hacker News and comment in Talmudic detail about what is right or wrong in the conclusions I drew. But a much better idea is to just email Sean and have a crack at the challenges yourself. You will have a good time!

One final observation. Crypto is like catnip for programmers. It is hard to keep us away from it, because it's challenging and fun to play with. And programmers respond very badly to the insinuation that they're not clever enough to do something. We see the F-16 just sitting there, keys in the ignition, no one watching, lights blinking, ladder extended. And some infosec nerd is telling us we're can't climb in there, even though we just want to taxi around a little and we've totally read the manual.

Doing these challenges is a great way to 'shake your sillies out', as Raffi might say, without hurting yourself or your users. You get to put on the flight suit, climb into the simulator, and crash that plane in every conceivable way.

I would like to sincerely thank Thomas and Sean and everyone at Matasano who worked on these challenges, and implore people in other technical fields to consider offering something similar. It's the most fun I've had programming in years!

—maciej on April 18, 2013
